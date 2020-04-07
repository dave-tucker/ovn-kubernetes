package ovn

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers/core/v1"
	networkListers "k8s.io/client-go/listers/networking/v1"
	"k8s.io/klog"
)

type PolicyController struct {
	namespaceInformer     informer.EventHandler
	podInformer           informer.EventHandler
	networkPolicyInformer informer.EventHandler

	namespaceLister     listers.NamespaceLister
	networkPolicyLister networkListers.NetworkPolicyLister

	// For each namespace, a map of policy name to 'namespacePolicy'.
	namespacePolicies map[string]map[string]*namespacePolicy

	// Port group for ingress deny rule
	portGroupIngressDeny string

	// Port group for egress deny rule
	portGroupEgressDeny string

	// For each logical port, the number of network policies that want
	// to add a ingress deny rule.
	lspIngressDenyCache map[string]int

	// For each logical port, the number of network policies that want
	// to add a egress deny rule.
	lspEgressDenyCache map[string]int

	// A mutex for lspIngressDenyCache and lspEgressDenyCache
	lspMutex *sync.Mutex

	logicalPortCache *portCache
}

type namespacePolicy struct {
	sync.Mutex
	name            string
	namespace       string
	ingressPolicies []*gressPolicy
	egressPolicies  []*gressPolicy
	// localPods is a map of pods effected by this policy
	localPods map[string]*lpInfo
	// portGroupUUID is the uuid for OVN port_group
	portGroupUUID string
	portGroupName string
	// deleted is true if this policy has been deleted
	deleted bool
}

func newNamespacePolicy(policy *knet.NetworkPolicy) *namespacePolicy {
	np := &namespacePolicy{
		name:            policy.Name,
		namespace:       policy.Namespace,
		ingressPolicies: make([]*gressPolicy, 0),
		egressPolicies:  make([]*gressPolicy, 0),
		localPods:       make(map[string]*lpInfo),
	}
	return np
}

func (pc *PolicyController) addPod(pod *kapi.Pod) error {
	for _, nps := range pc.namespacePolicies {
		for _, np := range nps {
			policy, err := pc.networkPolicyLister.NetworkPolicies(np.namespace).Get(np.name)
			if err != nil {
				return err
			}
			// localPods are those that the policy is applied to
			local, err := matchesSelector(&policy.Spec.PodSelector, pod.GetLabels())
			if err != nil {
				return err
			}
			if local {
				np.handleLocalPodSelectorAddFunc(policy, pod, pc)
				continue
			}
			gressPolicies := append(np.ingressPolicies, np.egressPolicies...)
			for _, p := range gressPolicies {
				var podMatch bool
				var nsMatch bool
				var err error

				if p.namespaceSelector == nil && p.podSelector == nil {
					return nil
				}

				if p.podSelector != nil {
					podMatch, err = matchesSelector(p.namespaceSelector, pod.GetLabels())
					if err != nil {
						return err
					}
				}

				if p.namespaceSelector != nil {
					ns, err := pc.namespaceLister.Get(pod.Namespace)
					if err != nil {
						return err
					}
					nsMatch, err = matchesSelector(p.namespaceSelector, ns.GetLabels())
					if err != nil {
						return err
					}
					if !nsMatch {
						return nil
					}
				}

				if nsMatch && p.podSelector == nil {
					np.handlePeerNamespaceSelectorAdd(policy)
					continue
				}
				if podMatch && p.namespaceSelector == nil {
					np.handlePeerPodSelectorAddUpdate(pod)
					continue
				}
				if podMatch && nsMatch {
					np.handlePeerPodSelectorAddUpdate(pod)
					continue
				}
			}
		}
	}
	return nil
}

func (pc *PolicyController) addNamespace(ns *kapi.Namespace) error {
	return nil
}

func (pc *PolicyController) deletePod(pod *kapi.Pod) error {
	for _, nps := range pc.namespacePolicies {
		for _, np := range nps {

			policy, err := pc.networkPolicyLister.NetworkPolicies(np.namespace).Get(np.name)
			if err != nil {
				return err
			}
			// localPods are those that the policy is applied to
			local, err := matchesSelector(&policy.Spec.PodSelector, pod.GetLabels())
			if err != nil {
				return err
			}
			if local {
				// Get the logical port info
				logicalPort := podLogicalPortName(pod)
				portInfo, err := pc.logicalPortCache.get(logicalPort)
				if err != nil {
					return err
				}
				np.handleLocalPodSelectorDelFunc(policy, pod, pc)
			}
			gressPolicies := append(np.ingressPolicies, np.egressPolicies...)
			for _, p := range gressPolicies {
				var podMatch bool
				var nsMatch bool
				var err error

				if p.namespaceSelector == nil && p.podSelector == nil {
					return nil
				}

				if p.podSelector != nil {
					podMatch, err = matchesSelector(p.namespaceSelector, pod.GetLabels())
					if err != nil {
						return err
					}
				}

				if p.namespaceSelector != nil {
					ns, err := pc.namespaceLister.Get(pod.Namespace)
					if err != nil {
						return err
					}
					nsMatch, err = matchesSelector(p.namespaceSelector, ns.GetLabels())
					if err != nil {
						return err
					}
					if !nsMatch {
						return nil
					}
				}

				if nsMatch && p.podSelector == nil {
					np.handlePeerNamespaceSelectorDelete(policy, p)
				}
				if podMatch && p.namespaceSelector == nil {
					np.handlePeerPodSelectorDelete(pod)
				}
				if podMatch && nsMatch {
					np.handlePeerPodSelectorDelete(pod)
					np.handlePeerPodSelectorDeleteACLRules(pod, pc)
				}
				continue
			}
		}
	}
	return nil
}

func (np *namespacePolicy) deleteNamespace(ns *kapi.Namespace) error {
	return nil
}

func matchesSelector(selector *metav1.LabelSelector, labels labels.Set) (bool, error) {
	s, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}
	return s.Matches(labels), nil
}

type gressPolicy struct {
	policyType knet.PolicyType
	idx        int

	// podSelector matches the pods this applies to
	podSelector *metav1.LabelSelector

	// namespaceSelector matches the pods this applies to
	namespaceSelector *metav1.LabelSelector

	// peerAddressSets points to all the addressSets that hold
	// the peer pod's IP addresses. We will have one addressSet for
	// local pods and multiple addressSets that each represent a
	// peer namespace
	peerAddressSets map[string]bool

	// sortedPeerAddressSets has the sorted peerAddressSets
	sortedPeerAddressSets []string

	// portPolicies represents all the ports to which traffic is allowed for
	// the rule in question.
	portPolicies []*portPolicy

	// ipBlockCidr represents the CIDR from which traffic is allowed
	// except the IP block in the except, which should be dropped.
	ipBlockCidr   []string
	ipBlockExcept []string

	// peerPodAddressMap represents the IP addresses of all the peer pods
	// for this ingress.
	peerPodAddressMap map[string]bool
}

type portPolicy struct {
	protocol string
	port     int32
}

func (pp *portPolicy) getL4Match() (string, error) {
	if pp.protocol == TCP {
		return fmt.Sprintf("tcp && tcp.dst==%d", pp.port), nil
	} else if pp.protocol == UDP {
		return fmt.Sprintf("udp && udp.dst==%d", pp.port), nil
	} else if pp.protocol == SCTP {
		return fmt.Sprintf("sctp && sctp.dst==%d", pp.port), nil
	}
	return "", fmt.Errorf("unknown port protocol %v", pp.protocol)
}

func newGressPolicy(policyType knet.PolicyType, idx int, podSelector, namespaceSelector *metav1.LabelSelector) *gressPolicy {
	return &gressPolicy{
		policyType:            policyType,
		idx:                   idx,
		peerAddressSets:       make(map[string]bool),
		sortedPeerAddressSets: make([]string, 0),
		portPolicies:          make([]*portPolicy, 0),
		ipBlockCidr:           make([]string, 0),
		ipBlockExcept:         make([]string, 0),
		podSelector:           podSelector,
		namespaceSelector:     namespaceSelector,
	}
}

func (gp *gressPolicy) addPortPolicy(portJSON *knet.NetworkPolicyPort) {
	gp.portPolicies = append(gp.portPolicies, &portPolicy{
		protocol: string(*portJSON.Protocol),
		port:     portJSON.Port.IntVal,
	})
}

func (gp *gressPolicy) addIPBlock(ipblockJSON *knet.IPBlock) {
	gp.ipBlockCidr = append(gp.ipBlockCidr, ipblockJSON.CIDR)
	gp.ipBlockExcept = append(gp.ipBlockExcept, ipblockJSON.Except...)
}

func ipMatch() string {
	if config.IPv6Mode {
		return "ip6"
	}
	return "ip4"
}

func (gp *gressPolicy) getL3MatchFromAddressSet() string {
	var l3Match, addresses string
	for _, addressSet := range gp.sortedPeerAddressSets {
		if addresses == "" {
			addresses = fmt.Sprintf("$%s", addressSet)
			continue
		}
		addresses = fmt.Sprintf("%s, $%s", addresses, addressSet)
	}
	if addresses == "" {
		l3Match = ipMatch()
	} else {
		if gp.policyType == knet.PolicyTypeIngress {
			l3Match = fmt.Sprintf("%s.src == {%s}", ipMatch(), addresses)
		} else {
			l3Match = fmt.Sprintf("%s.dst == {%s}", ipMatch(), addresses)
		}
	}
	return l3Match
}

func (gp *gressPolicy) getMatchFromIPBlock(lportMatch, l4Match string) string {
	var match string
	ipBlockCidr := fmt.Sprintf("{%s}", strings.Join(gp.ipBlockCidr, ", "))
	if gp.policyType == knet.PolicyTypeIngress {
		if l4Match == noneMatch {
			match = fmt.Sprintf("match=\"%s.src == %s && %s\"",
				ipMatch(), ipBlockCidr, lportMatch)
		} else {
			match = fmt.Sprintf("match=\"%s.src == %s && %s && %s\"",
				ipMatch(), ipBlockCidr, l4Match, lportMatch)
		}
	} else {
		if l4Match == noneMatch {
			match = fmt.Sprintf("match=\"%s.dst == %s && %s\"",
				ipMatch(), ipBlockCidr, lportMatch)
		} else {
			match = fmt.Sprintf("match=\"%s.dst == %s && %s && %s\"",
				ipMatch(), ipBlockCidr, l4Match, lportMatch)
		}
	}
	return match
}

func (gp *gressPolicy) addAddressSet(hashedAddressSet string) (string, string, bool) {
	if gp.peerAddressSets[hashedAddressSet] {
		return "", "", false
	}

	oldL3Match := gp.getL3MatchFromAddressSet()

	gp.sortedPeerAddressSets = append(gp.sortedPeerAddressSets, hashedAddressSet)
	sort.Strings(gp.sortedPeerAddressSets)
	gp.peerAddressSets[hashedAddressSet] = true

	return oldL3Match, gp.getL3MatchFromAddressSet(), true
}

func (gp *gressPolicy) delAddressSet(hashedAddressSet string) (string, string, bool) {
	if !gp.peerAddressSets[hashedAddressSet] {
		return "", "", false
	}

	oldL3Match := gp.getL3MatchFromAddressSet()

	for i, addressSet := range gp.sortedPeerAddressSets {
		if addressSet == hashedAddressSet {
			gp.sortedPeerAddressSets = append(
				gp.sortedPeerAddressSets[:i],
				gp.sortedPeerAddressSets[i+1:]...)
			break
		}
	}
	delete(gp.peerAddressSets, hashedAddressSet)

	return oldL3Match, gp.getL3MatchFromAddressSet(), true
}

const (
	toLport   = "to-lport"
	fromLport = "from-lport"
	noneMatch = "None"
	// Default deny acl rule priority
	defaultDenyPriority = "1000"
	// Default allow acl rule priority
	defaultAllowPriority = "1001"
	// IP Block except deny acl rule priority
	ipBlockDenyPriority = "1010"
	// Default multicast deny acl rule priority
	defaultMcastDenyPriority = "1011"
	// Default multicast allow acl rule priority
	defaultMcastAllowPriority = "1012"
)

func (oc *Controller) syncNetworkPolicies(networkPolicies []interface{}) {
	expectedPolicies := make(map[string]map[string]bool)
	for _, npInterface := range networkPolicies {
		policy, ok := npInterface.(*knet.NetworkPolicy)
		if !ok {
			klog.Errorf("Spurious object in syncNetworkPolicies: %v",
				npInterface)
			continue
		}

		if nsMap, ok := expectedPolicies[policy.Namespace]; ok {
			nsMap[policy.Name] = true
		} else {
			expectedPolicies[policy.Namespace] = map[string]bool{
				policy.Name: true,
			}
		}
	}

	err := oc.forEachAddressSetUnhashedName(func(addrSetName, namespaceName,
		policyName string) {
		if policyName != "" &&
			!expectedPolicies[namespaceName][policyName] {
			// policy doesn't exist on k8s. Delete the port group
			portGroupName := fmt.Sprintf("%s_%s", namespaceName, policyName)
			hashedLocalPortGroup := hashedPortGroup(portGroupName)
			deletePortGroup(hashedLocalPortGroup)

			// delete the address sets for this policy from OVN
			deleteAddressSet(hashedAddressSet(addrSetName))
		}
	})
	if err != nil {
		klog.Errorf("Error in syncing network policies: %v", err)
	}
}

func addAllowACLFromNode(logicalSwitch string, mgmtPortIP net.IP) error {
	match := fmt.Sprintf("%s.src==%s", ipMatch(), mgmtPortIP.String())
	_, stderr, err := util.RunOVNNbctl("--may-exist", "acl-add", logicalSwitch,
		"to-lport", defaultAllowPriority, match, "allow-related")
	if err != nil {
		return fmt.Errorf("failed to create the node acl for "+
			"logical_switch=%s, stderr: %q (%v)", logicalSwitch, stderr, err)
	}

	return nil
}

func addACLAllow(np *namespacePolicy, match, l4Match string, ipBlockCidr bool, gressNum int, policyType knet.PolicyType) {
	var direction, action string
	direction = toLport
	if policyType == knet.PolicyTypeIngress {
		action = "allow-related"
	} else {
		action = "allow"
	}

	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL",
		fmt.Sprintf("external-ids:l4Match=\"%s\"", l4Match),
		fmt.Sprintf("external-ids:ipblock_cidr=%t", ipBlockCidr),
		fmt.Sprintf("external-ids:namespace=%s", np.namespace),
		fmt.Sprintf("external-ids:policy=%s", np.name),
		fmt.Sprintf("external-ids:%s_num=%d", policyType, gressNum),
		fmt.Sprintf("external-ids:policy_type=%s", policyType))
	if err != nil {
		klog.Errorf("find failed to get the allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			np.namespace, np.name, stderr, err)
		return
	}

	if uuid != "" {
		return
	}

	_, stderr, err = util.RunOVNNbctl("--id=@acl", "create",
		"acl", fmt.Sprintf("priority=%s", defaultAllowPriority),
		fmt.Sprintf("direction=%s", direction), match,
		fmt.Sprintf("action=%s", action),
		fmt.Sprintf("external-ids:l4Match=\"%s\"", l4Match),
		fmt.Sprintf("external-ids:ipblock_cidr=%t", ipBlockCidr),
		fmt.Sprintf("external-ids:namespace=%s", np.namespace),
		fmt.Sprintf("external-ids:policy=%s", np.name),
		fmt.Sprintf("external-ids:%s_num=%d", policyType, gressNum),
		fmt.Sprintf("external-ids:policy_type=%s", policyType),
		"--", "add", "port_group", np.portGroupUUID, "acls", "@acl")
	if err != nil {
		klog.Errorf("failed to create the acl allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)", np.namespace,
			np.name, stderr, err)
		return
	}
}

func modifyACLAllow(namespace, policy, oldMatch string, newMatch string, gressNum int, policyType knet.PolicyType) {
	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", oldMatch,
		fmt.Sprintf("external-ids:namespace=%s", namespace),
		fmt.Sprintf("external-ids:policy=%s", policy),
		fmt.Sprintf("external-ids:%s_num=%d", policyType, gressNum),
		fmt.Sprintf("external-ids:policy_type=%s", policyType))
	if err != nil {
		klog.Errorf("find failed to get the allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			namespace, policy, stderr, err)
		return
	}

	if uuid != "" {
		// We already have an ACL. We will update it.
		_, stderr, err = util.RunOVNNbctl("set", "acl", uuid,
			newMatch)
		if err != nil {
			klog.Errorf("failed to modify the allow-from rule for "+
				"namespace=%s, policy=%s, stderr: %q (%v)",
				namespace, policy, stderr, err)
		}
		return
	}
}

func addIPBlockACLDeny(np *namespacePolicy, except, priority string, gressNum int, policyType knet.PolicyType) {
	var match, l3Match, direction, lportMatch string
	direction = toLport
	if policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", np.portGroupName)
		l3Match = fmt.Sprintf("%s.src == %s", ipMatch(), except)
		match = fmt.Sprintf("match=\"%s && %s\"", lportMatch, l3Match)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", np.portGroupName)
		l3Match = fmt.Sprintf("%s.dst == %s", ipMatch(), except)
		match = fmt.Sprintf("match=\"%s && %s\"", lportMatch, l3Match)
	}

	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action=drop",
		fmt.Sprintf("external-ids:ipblock-deny-policy-type=%s", policyType),
		fmt.Sprintf("external-ids:namespace=%s", np.namespace),
		fmt.Sprintf("external-ids:%s_num=%d", policyType, gressNum),
		fmt.Sprintf("external-ids:policy=%s", np.name))
	if err != nil {
		klog.Errorf("find failed to get the ipblock default deny rule for "+
			"namespace=%s, policy=%s stderr: %q, (%v)",
			np.namespace, np.name, stderr, err)
		return
	}

	if uuid != "" {
		return
	}

	_, stderr, err = util.RunOVNNbctl("--id=@acl", "create", "acl",
		fmt.Sprintf("priority=%s", priority),
		fmt.Sprintf("direction=%s", direction), match, "action=drop",
		fmt.Sprintf("external-ids:ipblock-deny-policy-type=%s", policyType),
		fmt.Sprintf("external-ids:%s_num=%d", policyType, gressNum),
		fmt.Sprintf("external-ids:namespace=%s", np.namespace),
		fmt.Sprintf("external-ids:policy=%s", np.name),
		"--", "add", "port_group", np.portGroupUUID,
		"acls", "@acl")
	if err != nil {
		klog.Errorf("error executing create ACL command, stderr: %q, %+v",
			stderr, err)
	}
}

func getACLMatch(portGroupName, match string, policyType knet.PolicyType) string {
	var aclMatch string
	if policyType == knet.PolicyTypeIngress {
		aclMatch = "outport == @" + portGroupName
	} else {
		aclMatch = "inport == @" + portGroupName
	}

	if match != "" {
		aclMatch += " && " + match
	}

	return "match=\"" + aclMatch + "\""
}

func addACLPortGroup(portGroupUUID, portGroupName, direction, priority, match, action string, policyType knet.PolicyType) error {
	match = getACLMatch(portGroupName, match, policyType)
	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType))
	if err != nil {
		return fmt.Errorf("find failed to get the default deny rule for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}

	if uuid != "" {
		return nil
	}

	_, stderr, err = util.RunOVNNbctl("--id=@acl", "create", "acl",
		fmt.Sprintf("priority=%s", priority),
		fmt.Sprintf("direction=%s", direction), match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType),
		"--", "add", "port_group", portGroupUUID,
		"acls", "@acl")
	if err != nil {
		return fmt.Errorf("error executing create ACL command for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}
	return nil
}

func deleteACLPortGroup(portGroupName, direction, priority, match, action string, policyType knet.PolicyType) error {
	match = getACLMatch(portGroupName, match, policyType)
	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType))
	if err != nil {
		return fmt.Errorf("find failed to get the rule for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}

	if uuid == "" {
		return nil
	}

	_, stderr, err = util.RunOVNNbctl("remove", "port_group",
		portGroupName, "acls", uuid)
	if err != nil {
		return fmt.Errorf("remove failed to delete the rule for "+
			"port_group=%s, stderr: %q (%v)", portGroupName, stderr, err)
	}

	return nil
}

func addToPortGroup(portGroup string, portInfo *lpInfo) error {
	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", portGroup, "ports", portInfo.uuid, "--",
		"add", "port_group", portGroup, "ports", portInfo.uuid)
	if err != nil {
		return fmt.Errorf("failed to add logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", portInfo.name, portGroup, stderr, err)
	}
	return nil
}

func deleteFromPortGroup(portGroup string, portInfo *lpInfo) error {
	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", portGroup, "ports", portInfo.uuid)
	if err != nil {
		return fmt.Errorf("failed to delete logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", portInfo.name, portGroup, stderr, err)
	}
	return nil
}

func localPodAddACL(np *namespacePolicy, gress *gressPolicy) {
	l3Match := gress.getL3MatchFromAddressSet()

	var lportMatch, cidrMatch string
	if gress.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", np.portGroupName)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", np.portGroupName)
	}

	// If IPBlock CIDR is not empty and except string [] is not empty,
	// add deny acl rule with priority ipBlockDenyPriority (1010).
	if len(gress.ipBlockCidr) > 0 && len(gress.ipBlockExcept) > 0 {
		except := fmt.Sprintf("{%s}", strings.Join(gress.ipBlockExcept, ", "))
		addIPBlockACLDeny(np, except, ipBlockDenyPriority, gress.idx, gress.policyType)
	}

	if len(gress.portPolicies) == 0 {
		match := fmt.Sprintf("match=\"%s && %s\"", l3Match,
			lportMatch)
		l4Match := noneMatch

		if len(gress.ipBlockCidr) > 0 {
			// Add ACL allow rule for IPBlock CIDR
			cidrMatch = gress.getMatchFromIPBlock(lportMatch, l4Match)
			addACLAllow(np, cidrMatch, l4Match, true, gress.idx, gress.policyType)
		}
		// if there are pod/namespace selector, then allow packets from/to that address_set or
		// if the NetworkPolicyPeer is empty, then allow from all sources or to all destinations.
		if len(gress.sortedPeerAddressSets) > 0 || len(gress.ipBlockCidr) == 0 {
			addACLAllow(np, match, l4Match, false, gress.idx, gress.policyType)
		}
	}
	for _, port := range gress.portPolicies {
		l4Match, err := port.getL4Match()
		if err != nil {
			continue
		}
		match := fmt.Sprintf("match=\"%s && %s && %s\"",
			l3Match, l4Match, lportMatch)
		if len(gress.ipBlockCidr) > 0 {
			// Add ACL allow rule for IPBlock CIDR
			cidrMatch = gress.getMatchFromIPBlock(lportMatch, l4Match)
			addACLAllow(np, cidrMatch, l4Match, true, gress.idx, gress.policyType)
		}
		if len(gress.sortedPeerAddressSets) > 0 || len(gress.ipBlockCidr) == 0 {
			addACLAllow(np, match, l4Match, false, gress.idx, gress.policyType)
		}
	}
}

func createDefaultDenyPortGroup(policyType knet.PolicyType) (string, error) {
	var portGroupName string
	if policyType == knet.PolicyTypeIngress {
		portGroupName = "ingressDefaultDeny"
	} else if policyType == knet.PolicyTypeEgress {
		portGroupName = "egressDefaultDeny"
	}
	portGroupUUID, err := createPortGroup(portGroupName, portGroupName)
	if err != nil {
		return "", fmt.Errorf("Failed to create port_group for %s (%v)",
			portGroupName, err)
	}
	err = addACLPortGroup(portGroupUUID, portGroupName, toLport,
		defaultDenyPriority, "", "drop", policyType)
	if err != nil {
		return "", fmt.Errorf("Failed to create default deny ACL for port group %v", err)
	}

	err = addACLPortGroup(portGroupUUID, portGroupName, toLport,
		defaultAllowPriority, "arp", "allow", policyType)
	if err != nil {
		return "", fmt.Errorf("Failed to create default allow ARP ACL for port group %v", err)
	}
	return portGroupUUID, nil
}

// Creates the match string used for ACLs allowing incoming multicast into a
// namespace, that is, from IPs that are in the namespace's address set.
func getMulticastACLMatch(ns string) string {
	nsAddressSet := hashedAddressSet(ns)
	return "ip4.src == $" + nsAddressSet + " && ip4.mcast"
}

// Returns the multicast port group name and hash for namespace 'ns'.
func getMulticastPortGroup(ns string) (string, string) {
	portGroupName := "mcastPortGroup-" + ns
	return portGroupName, hashedPortGroup(portGroupName)
}

// Creates a policy to allow multicast traffic within 'ns':
// - a port group containing all logical ports associated with 'ns'
// - one "from-lport" ACL allowing egress multicast traffic from the pods
//   in 'ns'
// - one "to-lport" ACL allowing ingress multicast traffic to pods in 'ns'.
//   This matches only traffic originated by pods in 'ns' (based on the
//   namespace address set).
func (oc *Controller) createMulticastAllowPolicy(ns string) error {
	portGroupName, portGroupHash := getMulticastPortGroup(ns)
	portGroupUUID, err := createPortGroup(portGroupName, portGroupHash)
	if err != nil {
		return fmt.Errorf("Failed to create port_group for %s (%v)",
			portGroupName, err)
	}

	err = addACLPortGroup(portGroupUUID, portGroupHash, fromLport,
		defaultMcastAllowPriority, "ip4.mcast", "allow",
		knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("Failed to create allow egress multicast ACL for %s (%v)",
			ns, err)
	}

	err = addACLPortGroup(portGroupUUID, portGroupHash, toLport,
		defaultMcastAllowPriority, getMulticastACLMatch(ns), "allow",
		knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("Failed to create allow ingress multicast ACL for %s (%v)",
			ns, err)
	}

	// Add all ports from this namespace to the multicast allow group.
	for _, portName := range oc.namespaceAddressSet[ns] {
		if portInfo, err := oc.logicalPortCache.get(portName); err != nil {
			klog.Errorf(err.Error())
		} else if err := podAddAllowMulticastPolicy(ns, portInfo); err != nil {
			klog.Warningf("failed to add port %s to port group ACL: %v", portName, err)
		}
	}

	return nil
}

// Delete the policy to allow multicast traffic within 'ns'.
func deleteMulticastAllowPolicy(ns string) error {
	_, portGroupHash := getMulticastPortGroup(ns)

	err := deleteACLPortGroup(portGroupHash, fromLport,
		defaultMcastAllowPriority, "ip4.mcast", "allow",
		knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("Failed to delete allow egress multicast ACL for %s (%v)",
			ns, err)
	}

	err = deleteACLPortGroup(portGroupHash, toLport,
		defaultMcastAllowPriority, getMulticastACLMatch(ns), "allow",
		knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("Failed to delete allow ingress multicast ACL for %s (%v)",
			ns, err)
	}

	deletePortGroup(portGroupHash)
	return nil
}

// Creates a global default deny multicast policy:
// - one ACL dropping egress multicast traffic from all pods: this is to
//   protect OVN controller from processing IP multicast reports from nodes
//   that are not allowed to receive multicast raffic.
// - one ACL dropping ingress multicast traffic to all pods.
func createDefaultDenyMulticastPolicy() error {
	portGroupName := "mcastPortGroupDeny"
	portGroupUUID, err := createPortGroup(portGroupName, portGroupName)
	if err != nil {
		return fmt.Errorf("Failed to create port_group for %s (%v)",
			portGroupName, err)
	}

	// By default deny any egress multicast traffic from any pod. This drops
	// IP multicast membership reports therefore denying any multicast traffic
	// to be forwarded to pods.
	err = addACLPortGroup(portGroupUUID, portGroupName, fromLport,
		defaultMcastDenyPriority, "ip4.mcast", "drop", knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("Failed to create default deny multicast egress ACL (%v)",
			err)
	}

	// By default deny any ingress multicast traffic to any pod.
	err = addACLPortGroup(portGroupUUID, portGroupName, toLport,
		defaultMcastDenyPriority, "ip4.mcast", "drop", knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("Failed to create default deny multicast ingress ACL (%v)",
			err)
	}

	return nil
}

func podAddDefaultDenyMulticastPolicy(portInfo *lpInfo) error {
	if err := addToPortGroup("mcastPortGroupDeny", portInfo); err != nil {
		return fmt.Errorf("failed to add port %s to default multicast deny ACL: %v", portInfo.name, err)
	}
	return nil
}

func podDeleteDefaultDenyMulticastPolicy(portInfo *lpInfo) error {
	if err := deleteFromPortGroup("mcastPortGroupDeny", portInfo); err != nil {
		return fmt.Errorf("failed to delete port %s from default multicast deny ACL: %v", portInfo.name, err)
	}
	return nil
}

func podAddAllowMulticastPolicy(ns string, portInfo *lpInfo) error {
	_, portGroupHash := getMulticastPortGroup(ns)
	return addToPortGroup(portGroupHash, portInfo)
}

func podDeleteAllowMulticastPolicy(ns string, portInfo *lpInfo) error {
	_, portGroupHash := getMulticastPortGroup(ns)
	return deleteFromPortGroup(portGroupHash, portInfo)
}

func (np *namespacePolicy) localPodAddDefaultDeny(
	policy *knet.NetworkPolicy, portInfo *lpInfo, pc *PolicyController) {
	pc.lspMutex.Lock()
	defer pc.lspMutex.Unlock()

	var err error
	if pc.portGroupIngressDeny == "" {
		if pc.portGroupIngressDeny, err = createDefaultDenyPortGroup(knet.PolicyTypeIngress); err != nil {
			klog.Errorf(err.Error())
			return
		}
	}
	if pc.portGroupEgressDeny == "" {
		if pc.portGroupEgressDeny, err = createDefaultDenyPortGroup(knet.PolicyTypeEgress); err != nil {
			klog.Errorf(err.Error())
			return
		}
	}

	// Default deny rule.
	// 1. Any pod that matches a network policy should get a default
	// ingress deny rule.  This is irrespective of whether there
	// is a ingress section in the network policy. But, if
	// PolicyTypes in the policy has only "egress" in it, then
	// it is a 'egress' only network policy and we should not
	// add any default deny rule for ingress.
	// 2. If there is any "egress" section in the policy or
	// the PolicyTypes has 'egress' in it, we add a default
	// egress deny rule.

	// Handle condition 1 above.
	if !(len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) {
		if pc.lspIngressDenyCache[portInfo.name] == 0 {
			if err := addToPortGroup(pc.portGroupIngressDeny, portInfo); err != nil {
				klog.Warningf("failed to add port %s to ingress deny ACL: %v", portInfo.name, err)
			}
		}
		pc.lspIngressDenyCache[portInfo.name]++
	}

	// Handle condition 2 above.
	if (len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) ||
		len(policy.Spec.Egress) > 0 || len(policy.Spec.PolicyTypes) == 2 {
		if pc.lspEgressDenyCache[portInfo.name] == 0 {
			if err := addToPortGroup(pc.portGroupEgressDeny, portInfo); err != nil {
				klog.Warningf("failed to add port %s to egress deny ACL: %v", portInfo.name, err)
			}
		}
		pc.lspEgressDenyCache[portInfo.name]++
	}
}

func (np *namespacePolicy) localPodDelDefaultDeny(
	policy *knet.NetworkPolicy, portInfo *lpInfo, pc *PolicyController) {
	pc.lspMutex.Lock()
	defer pc.lspMutex.Unlock()

	if !(len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) {
		if pc.lspIngressDenyCache[portInfo.name] > 0 {
			pc.lspIngressDenyCache[portInfo.name]--
			if pc.lspIngressDenyCache[portInfo.name] == 0 {
				if err := deleteFromPortGroup(pc.portGroupIngressDeny, portInfo); err != nil {
					klog.Warningf("failed to remove port %s from ingress deny ACL: %v", portInfo.name, err)
				}
			}
		}
	}

	if (len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) ||
		len(policy.Spec.Egress) > 0 || len(policy.Spec.PolicyTypes) == 2 {
		if pc.lspEgressDenyCache[portInfo.name] > 0 {
			pc.lspEgressDenyCache[portInfo.name]--
			if pc.lspEgressDenyCache[portInfo.name] == 0 {
				if err := deleteFromPortGroup(pc.portGroupEgressDeny, portInfo); err != nil {
					klog.Warningf("failed to remove port %s from egress deny ACL: %v", portInfo.name, err)
				}
			}
		}
	}
}

func (np *namespacePolicy) handleLocalPodSelectorAddFunc(policy *knet.NetworkPolicy, pod *kapi.Pod, pc *PolicyController) {
	if pod.Spec.NodeName == "" {
		return
	}

	// Get the logical port info
	logicalPort := podLogicalPortName(pod)
	portInfo, err := pc.logicalPortCache.get(logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	np.Lock()
	defer np.Unlock()

	if np.deleted {
		return
	}

	if _, ok := np.localPods[logicalPort]; ok {
		return
	}

	np.localPodAddDefaultDeny(policy, portInfo, pc)

	if np.portGroupUUID == "" {
		return
	}

	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", np.portGroupUUID, "ports", portInfo.uuid, "--",
		"add", "port_group", np.portGroupUUID, "ports", portInfo.uuid)
	if err != nil {
		klog.Errorf("Failed to add logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", logicalPort, np.portGroupUUID, stderr, err)
	}

	np.localPods[logicalPort] = portInfo
}

func (np *namespacePolicy) handleLocalPodSelectorDelFunc(policy *knet.NetworkPolicy, pod *kapi.Pod, pc *PolicyController) {
	if pod.Spec.NodeName == "" {
		return
	}

	// Get the logical port info
	logicalPort := podLogicalPortName(pod)
	portInfo, err := pc.logicalPortCache.get(logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	np.Lock()
	defer np.Unlock()

	if np.deleted {
		return
	}

	if _, ok := np.localPods[logicalPort]; !ok {
		return
	}
	delete(np.localPods, logicalPort)
	np.localPodDelDefaultDeny(policy, portInfo, pc)

	pc.lspMutex.Lock()
	delete(pc.lspIngressDenyCache, logicalPort)
	delete(pc.lspEgressDenyCache, logicalPort)
	pc.lspMutex.Unlock()

	if np.portGroupUUID == "" {
		return
	}

	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", np.portGroupUUID, "ports", portInfo.uuid)
	if err != nil {
		klog.Errorf("Failed to delete logicalPort %s from portGroup %s "+
			"stderr: %q (%v)", portInfo.uuid, np.portGroupUUID, stderr, err)
	}
}

func handlePeerNamespaceSelectorModify(
	gress *gressPolicy, np *namespacePolicy, oldl3Match, newl3Match string) {

	var lportMatch string
	if gress.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", np.portGroupName)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", np.portGroupName)
	}
	if len(gress.portPolicies) == 0 {
		oldMatch := fmt.Sprintf("match=\"%s && %s\"", oldl3Match,
			lportMatch)
		newMatch := fmt.Sprintf("match=\"%s && %s\"", newl3Match,
			lportMatch)
		modifyACLAllow(np.namespace, np.name, oldMatch, newMatch, gress.idx, gress.policyType)
	}
	for _, port := range gress.portPolicies {
		l4Match, err := port.getL4Match()
		if err != nil {
			continue
		}
		oldMatch := fmt.Sprintf("match=\"%s && %s && %s\"",
			oldl3Match, l4Match, lportMatch)
		newMatch := fmt.Sprintf("match=\"%s && %s && %s\"",
			newl3Match, l4Match, lportMatch)
		modifyACLAllow(np.namespace, np.name, oldMatch, newMatch, gress.idx, gress.policyType)
	}
}

// we only need to create an address set if there is a podSelector or namespaceSelector
func hasAnyLabelSelector(peers []knet.NetworkPolicyPeer) bool {
	for _, peer := range peers {
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			return true
		}
	}
	return false
}

type peerPodSelectorData struct {
}

// addNetworkPolicy creates and applies OVN ACLs to pod logical switch
// ports from Kubernetes NetworkPolicy objects using OVN Port Groups
func (pc *PolicyController) addNetworkPolicy(policy *knet.NetworkPolicy) error {
	klog.Infof("Adding network policy %s in namespace %s", policy.Name,
		policy.Namespace)

	if pc.namespacePolicies[policy.Namespace] != nil &&
		pc.namespacePolicies[policy.Namespace][policy.Name] != nil {
		return nil
	}

	// Wait for 10 seconds to get the namespace event.
	count := 100
	for {
		if pc.namespacePolicies[policy.Namespace] != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
		count--
		if count == 0 {
			return fmt.Errorf("timeout waiting for namespace %s event", policy.Namespace)
		}
	}

	np := newNamespacePolicy(policy)

	// Create a port group for the policy. All the pods that this policy
	// selects will be eventually added to this port group.
	readableGroupName := fmt.Sprintf("%s_%s", policy.Namespace, policy.Name)
	np.portGroupName = hashedPortGroup(readableGroupName)

	var err error
	np.portGroupUUID, err = createPortGroup(readableGroupName, np.portGroupName)
	if err != nil {
		return fmt.Errorf("Failed to create port_group for network policy %s in "+
			"namespace %s", policy.Name, policy.Namespace)
	}

	// Go through each ingress rule.  For each ingress rule, create an
	// addressSet for the peer pods.
	for i, ingressJSON := range policy.Spec.Ingress {
		klog.V(5).Infof("Network policy ingress is %+v", ingressJSON)

		ingress := newGressPolicy(knet.PolicyTypeIngress, i)

		// Each ingress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range ingressJSON.Ports {
			ingress.addPortPolicy(&portJSON)
		}

		hashedLocalAddressSet := ""

		if hasAnyLabelSelector(ingressJSON.From) {
			// localPeerPods represents all the peer pods in the same
			// namespace from which we need to allow traffic.
			localPeerPods := fmt.Sprintf("%s.%s.%s.%d", policy.Namespace,
				policy.Name, "ingress", i)

			hashedLocalAddressSet = hashedAddressSet(localPeerPods)
			createAddressSet(localPeerPods, hashedLocalAddressSet, nil)
			ingress.addAddressSet(hashedLocalAddressSet)
		}

		for _, fromJSON := range ingressJSON.From {
			// Add IPBlock to ingress network policy
			if fromJSON.IPBlock != nil {
				ingress.addIPBlock(fromJSON.IPBlock)
			}
		}

		localPodAddACL(np, ingress)

		for _, fromJSON := range ingressJSON.From {
			/*
				if fromJSON.NamespaceSelector != nil && fromJSON.PodSelector != nil {
					// For each rule that contains both peer namespace selector and
					// peer pod selector, we create a watcher for each matching namespace
					// that populates the addressSet
					oc.handlePeerNamespaceAndPodSelector(policy, ingress,
						fromJSON.NamespaceSelector, fromJSON.PodSelector,
						ingress.peerAddressSets, peerPodAddressMap, np)

				} else if fromJSON.NamespaceSelector != nil {
					// For each peer namespace selector, we create a watcher that
					// populates ingress.peerAddressSets
					oc.handlePeerNamespaceSelector(policy,
						fromJSON.NamespaceSelector, ingress, np,
						oc.handlePeerNamespaceSelectorModify)
				} else if fromJSON.PodSelector != nil {
					// For each peer pod selector, we create a watcher that
					// populates the addressSet
					oc.handlePeerPodSelector(policy, fromJSON.PodSelector,
						hashedLocalAddressSet, peerPodAddressMap, np)
				}
			*/
		}
		np.ingressPolicies = append(np.ingressPolicies, ingress)
	}

	// Go through each egress rule.  For each egress rule, create an
	// addressSet for the peer pods.
	for i, egressJSON := range policy.Spec.Egress {
		klog.V(5).Infof("Network policy egress is %+v", egressJSON)

		egress := newGressPolicy(knet.PolicyTypeEgress, i)

		// Each egress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range egressJSON.Ports {
			egress.addPortPolicy(&portJSON)
		}

		hashedLocalAddressSet := ""
		// peerPodAddressMap represents the IP addresses of all the peer pods
		// for this egress.
		peerPodAddressMap := make(map[string]bool)
		if hasAnyLabelSelector(egressJSON.To) {
			// localPeerPods represents all the peer pods in the same
			// namespace to which we need to allow traffic.
			localPeerPods := fmt.Sprintf("%s.%s.%s.%d", policy.Namespace,
				policy.Name, "egress", i)

			hashedLocalAddressSet = hashedAddressSet(localPeerPods)
			createAddressSet(localPeerPods, hashedLocalAddressSet, nil)
			egress.addAddressSet(hashedLocalAddressSet)
		}

		for _, toJSON := range egressJSON.To {
			// Add IPBlock to egress network policy
			if toJSON.IPBlock != nil {
				egress.addIPBlock(toJSON.IPBlock)
			}
		}

		localPodAddACL(np, egress)

		for _, toJSON := range egressJSON.To {
			/*
				if toJSON.NamespaceSelector != nil && toJSON.PodSelector != nil {
					// For each rule that contains both peer namespace selector and
					// peer pod selector, we create a watcher for each matching namespace
					// that populates the addressSet
					oc.handlePeerNamespaceAndPodSelector(policy, egress,
						toJSON.NamespaceSelector, toJSON.PodSelector,
						hashedLocalAddressSet, peerPodAddressMap, np)

				} else if toJSON.NamespaceSelector != nil {
					// For each peer namespace selector, we create a watcher that
					// populates egress.peerAddressSets
					oc.handlePeerNamespaceSelector(policy,
						toJSON.NamespaceSelector, egress, np,
						oc.handlePeerNamespaceSelectorModify)
				} else if toJSON.PodSelector != nil {
					// For each peer pod selector, we create a watcher that
					// populates the addressSet
					oc.handlePeerPodSelector(policy, toJSON.PodSelector,
						hashedLocalAddressSet, peerPodAddressMap, np)
				}
			*/
		}
		np.egressPolicies = append(np.egressPolicies, egress)
	}

	pc.namespacePolicies[policy.Namespace][policy.Name] = np

	// The namespacePolicy will be checked each time a pod
	// is added/deleted in the local namespace that this policy
	// effects, adding them to the port group.

	return nil
}

func (pc *PolicyController) deleteNetworkPolicy(policy *knet.NetworkPolicy) error {
	klog.Infof("Deleting network policy %s in namespace %s",
		policy.Name, policy.Namespace)

	if pc.namespacePolicies[policy.Namespace] == nil ||
		pc.namespacePolicies[policy.Namespace][policy.Name] == nil {
		return fmt.Errorf("Delete network policy %s in namespace %s "+
			"received without getting a create event",
			policy.Name, policy.Namespace)
	}
	np := pc.namespacePolicies[policy.Namespace][policy.Name]

	np.Lock()
	defer np.Unlock()

	// Mark the policy as deleted.
	np.deleted = true

	for _, portInfo := range np.localPods {
		pc.localPodDelDefaultDeny(policy, portInfo)
	}

	// Delete the port group
	deletePortGroup(np.portGroupName)

	// Go through each ingress rule.  For each ingress rule, delete the
	// addressSet for the local peer pods.
	for i := range np.ingressPolicies {
		localPeerPods := fmt.Sprintf("%s.%s.%s.%d", policy.Namespace,
			policy.Name, "ingress", i)
		hashedAddressSet := hashedAddressSet(localPeerPods)
		deleteAddressSet(hashedAddressSet)
	}
	// Go through each egress rule.  For each egress rule, delete the
	// addressSet for the local peer pods.
	for i := range np.egressPolicies {
		localPeerPods := fmt.Sprintf("%s.%s.%s.%d", policy.Namespace,
			policy.Name, "egress", i)
		hashedAddressSet := hashedAddressSet(localPeerPods)
		deleteAddressSet(hashedAddressSet)
	}

	pc.namespacePolicies[policy.Namespace][policy.Name] = nil
	return nil
}

// handlePeerPodSelectorAddUpdate adds the IP address of a pod that has been
// selected as a peer by a NetworkPolicy's ingress/egress section to that
// ingress/egress address set
func (np *namespacePolicy) handlePeerPodSelectorAddUpdate(pod *kapi.Pod) {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
	if err != nil {
		return
	}
	ipAddress := podAnnotation.IP.IP.String()

	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}

	gress := append(np.ingressPolicies, np.egressPolicies...)
	for _, g := range gress {
		if g.peerPodAddressMap[ipAddress] {
			continue
		}
		g.peerPodAddressMap[ipAddress] = true
		addToAddressSet(g.peerAddressSet, ipAddress)
	}
}

func (np *namespacePolicy) handlePeerPodSelectorDeleteACLRules(pod *kapi.Pod, pc *PolicyController) {
	logicalPort := podLogicalPortName(pod)
	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}
	pc.lspMutex.Lock()
	delete(pc.lspIngressDenyCache, logicalPort)
	delete(pc.lspEgressDenyCache, logicalPort)
	pc.lspMutex.Unlock()
}

// handlePeerPodSelectorDelete removes the IP address of a pod that no longer
// matches a NetworkPolicy ingress/egress section's selectors from that
// ingress/egress address set
func (np *namespacePolicy) handlePeerPodSelectorDelete(pod *kapi.Pod) {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
	if err != nil {
		return
	}
	ipAddress := podAnnotation.IP.IP.String()

	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}
	gress := append(np.ingressPolicies, np.egressPolicies...)
	for _, g := range gress {
		if !g.peerPodAddressMap[ipAddress] {
			return
		}
		delete(g.peerPodAddressMap, ipAddress)
		removeFromAddressSet(p.peerAddressSet, ipAddress)
	}
}

func (np *namespacePolicy) handlePeerNamespaceSelectorAdd(policy *knet.NetworkPolicy) {
	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}

	gress := append(np.ingress, np.egress...)
	for _, g := range gress {
		hashedAddressSet := hashedAddressSet(namespace.Name)
		oldL3Match, newL3Match, added := g.addAddressSet(hashedAddressSet)
		if added {
			handlePeerNamespaceSelectorModify(g, np, oldL3Match, newL3Match)
		}
	}
}

func (np *namespacePolicy) handlePeerNamespaceSelectorDelete(policy *knet.NetworkPolicy, gress *gressPolicy) {
	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}
	hashedAddressSet := hashedAddressSet(namespace.Name)
	oldL3Match, newL3Match, removed := gress.delAddressSet(hashedAddressSet)
	if removed {
		handlePeerNamespaceSelectorModify(gress, np, oldL3Match, newL3Match)
	}
}
