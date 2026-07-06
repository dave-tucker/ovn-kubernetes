// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovnkubernetes

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	cncv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/clusternetworkconnect/v1"
	cnclisters "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/clusternetworkconnect/v1/apis/listers/clusternetworkconnect/v1"
	udnv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	udnlisters "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/listers/userdefinednetwork/v1"
	ovntypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"

	"github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes/object"
)

const (
	// maxDNSLabelLen is the maximum DNS label length per RFC 1035.
	maxDNSLabelLen = 63

	// networkKeyPrefixCUDN distinguishes CUDN keys from UDN keys in maps
	// where both share a "name" format.
	networkKeyPrefixCUDN = "cudn:"
)

// internalNetKey returns the key used for a network in the cncPeers map and
// the autopath search path logic.
//   - UDN  → "namespace/udn-name"   (same as the NAD key)
//   - CUDN → "cudn:cudn-name"
func internalNetKey(namespace, name string, isCUDN bool) string {
	if isCUDN {
		return networkKeyPrefixCUDN + name
	}
	return namespace + "/" + name
}

// podNetworksAnnotation mirrors the per-NAD JSON object stored under
// k8s.ovn.org/pod-networks.
type podNetworksAnnotation struct {
	IPs []string `json:"ip_addresses"`
	// ip_address is the deprecated single-IP field (backward compat).
	IP string `json:"ip_address,omitempty"`
	// Routes are additional routes added to the pod's interface.
	Routes []struct {
		Dest    string `json:"dest"`
		NextHop string `json:"nextHop"`
	} `json:"routes,omitempty"`
}

// Cache holds all in-memory state built from informer events.
// All exported accessor methods are safe for concurrent use.
type Cache struct {
	mu sync.RWMutex

	// udnIPIndex maps any IP belonging to a UDN pod to the Pod struct.
	// Indexed IPs include:
	//   - UDN/CUDN primary IPs (the pod's network-specific addresses)
	//   - The pod's infrastructure-locked default-network IPs (for cases
	//     where the DNS query arrives from the default interface)
	udnIPIndex map[string]*object.Pod

	// ovnInternalCIDRs holds subnets that OVN-K uses internally for SNAT
	// (join subnet, transit subnet). DNS queries from these IPs originate
	// from UDN pods whose real IP was SNAT'd by the OVN Gateway Router.
	// We cannot determine which UDN the pod belongs to from the source IP
	// alone, so these sources are allowed through — the OVN data-plane
	// already enforces network boundaries.
	// Populated automatically from the routes in pod default-network annotations.
	ovnInternalCIDRs []*net.IPNet

	// pods holds every pod with ≥1 UDN/CUDN IP, keyed by "namespace/name".
	pods map[string]*object.Pod

	// udnNames is the set of known UDN keys ("namespace/udn-name").
	udnNames map[string]struct{}

	// cudnNames is the set of known CUDN names.
	cudnNames map[string]struct{}

	// udnSubnets maps UDN key ("ns/name") → pod CIDRs.
	udnSubnets map[string][]*net.IPNet

	// cudnSubnets maps CUDN name → pod CIDRs.
	cudnSubnets map[string][]*net.IPNet

	// cncPeers maps an internal network key to its direct peers (from CNC).
	cncPeers map[string][]string

	// cncNetworks records which network keys each CNC contributes, so they
	// can be retracted on update/delete.
	cncNetworks map[string][]string

	// listers used during CNC resolution.
	udnLister  udnlisters.UserDefinedNetworkLister
	cudnLister udnlisters.ClusterUserDefinedNetworkLister
	cncLister  cnclisters.ClusterNetworkConnectLister // stored but unused for now
}

// newCache allocates a ready-to-use Cache.
func newCache() *Cache {
	return &Cache{
		udnIPIndex:  make(map[string]*object.Pod),
		pods:        make(map[string]*object.Pod),
	
		udnNames:    make(map[string]struct{}),
		cudnNames:   make(map[string]struct{}),
		udnSubnets:  make(map[string][]*net.IPNet),
		cudnSubnets: make(map[string][]*net.IPNet),
		cncPeers:    make(map[string][]string),
		cncNetworks: make(map[string][]string),
	}
}

// ---- Pod event handlers ----

// OnPodAdd indexes a newly-created pod.
func (c *Cache) OnPodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addPodLocked(pod)
}

// OnPodUpdate re-indexes a pod when its annotations change.
func (c *Cache) OnPodUpdate(oldObj, newObj interface{}) {
	old, ok1 := oldObj.(*corev1.Pod)
	nw, ok2 := newObj.(*corev1.Pod)
	if !ok1 || !ok2 {
		return
	}
	if old.ResourceVersion == nw.ResourceVersion {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removePodLocked(old)
	c.addPodLocked(nw)
}

// OnPodDelete removes a pod from the index.
func (c *Cache) OnPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		if d, ok2 := obj.(cache.DeletedFinalStateUnknown); ok2 {
			pod, ok = d.Obj.(*corev1.Pod)
			if !ok {
				return
			}
		} else {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removePodLocked(pod)
}

func (c *Cache) addPodLocked(pod *corev1.Pod) {
	annot, ok := pod.Annotations[ovntypes.OvnPodAnnotationName]
	if !ok {
		return
	}

	var networks map[string]podNetworksAnnotation
	if err := json.Unmarshal([]byte(annot), &networks); err != nil {
		klog.V(4).InfoS("ovn-kubernetes CoreDNS: failed to unmarshal pod annotation",
			"pod", pod.Namespace+"/"+pod.Name, "err", err)
		return
	}

	p := &object.Pod{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Hostname:  pod.Spec.Hostname,
		Subdomain: pod.Spec.Subdomain,
		UDNIPs:    make(map[string][]net.IP),
	}

	for nadKey, entry := range networks {
		if nadKey == "default" {
			continue
		}
		ips := collectIPs(entry)
		if len(ips) == 0 {
			continue
		}
		p.UDNIPs[nadKey] = ips
		for _, ip := range ips {
			c.udnIPIndex[ip.String()] = p
		}
	}

	if len(p.UDNIPs) == 0 {
		// Pod has no UDN/CUDN attachments — not relevant to UDN DNS.
		return
	}

	// Index the pod's default-network IPs so DNS queries arriving from the
	// infrastructure-locked interface are still attributed to this pod.
	//
	// Also discover OVN-internal subnets from the default-network routes.
	// In OVN-K, UDN pod traffic to ClusterIP services is SNAT'd by the OVN
	// Gateway Router to the node's join-subnet IP (e.g. 100.64.0.2). CoreDNS
	// therefore sees the join-subnet IP as the source, not the UDN pod IP.
	// The join-subnet CIDR appears as a route in the default-network annotation
	// and is outside normal pod/service address space (10.x/172.x/192.168.x).
	if defaultEntry, ok := networks["default"]; ok {
		p.DefaultIPs = collectIPs(defaultEntry)
		for _, ip := range p.DefaultIPs {
			c.udnIPIndex[ip.String()] = p
		}
		for _, route := range defaultEntry.Routes {
			if _, cidr, err := net.ParseCIDR(route.Dest); err == nil {
				if isOVNInternalCIDR(cidr) {
					c.addOVNInternalCIDRLocked(cidr)
				}
			}
		}
	}

	c.pods[pod.Namespace+"/"+pod.Name] = p
	klog.V(4).InfoS("ovn-kubernetes CoreDNS: indexed pod",
		"pod", pod.Namespace+"/"+pod.Name,
		"udnNADs", len(p.UDNIPs),
		"defaultIPs", len(p.DefaultIPs))
}

func (c *Cache) removePodLocked(pod *corev1.Pod) {
	key := pod.Namespace + "/" + pod.Name
	p, ok := c.pods[key]
	if !ok {
		return
	}
	for _, ips := range p.UDNIPs {
		for _, ip := range ips {
			delete(c.udnIPIndex, ip.String())
		}
	}
	// Also remove default-network IPs that were indexed for this pod.
	for _, ip := range p.DefaultIPs {
		delete(c.udnIPIndex, ip.String())
	}
	delete(c.pods, key)
}

// collectIPs parses all IPs from a pod-networks annotation entry.
// IPs may be stored with a prefix length ("10.128.1.5/24") or plain.
func collectIPs(entry podNetworksAnnotation) []net.IP {
	var out []net.IP
	for _, s := range entry.IPs {
		if ip, _, err := net.ParseCIDR(s); err == nil {
			out = append(out, ip)
		} else if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	if len(out) == 0 && entry.IP != "" {
		if ip, _, err := net.ParseCIDR(entry.IP); err == nil {
			out = append(out, ip)
		} else if ip := net.ParseIP(entry.IP); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// ---- UDN event handlers ----

// OnUDNAdd indexes a newly-created UserDefinedNetwork.
func (c *Cache) OnUDNAdd(obj interface{}) {
	udn, ok := obj.(*udnv1.UserDefinedNetwork)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addUDNLocked(udn)
}

// OnUDNUpdate re-indexes a UserDefinedNetwork.
func (c *Cache) OnUDNUpdate(_, newObj interface{}) {
	udn, ok := newObj.(*udnv1.UserDefinedNetwork)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addUDNLocked(udn)
}

// OnUDNDelete removes a UserDefinedNetwork from the index.
func (c *Cache) OnUDNDelete(obj interface{}) {
	udn, ok := obj.(*udnv1.UserDefinedNetwork)
	if !ok {
		if d, ok2 := obj.(cache.DeletedFinalStateUnknown); ok2 {
			udn, ok = d.Obj.(*udnv1.UserDefinedNetwork)
			if !ok {
				return
			}
		} else {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := udnNADKey(udn.Namespace, udn.Name)
	delete(c.udnNames, key)
	delete(c.udnSubnets, key)
}

func (c *Cache) addUDNLocked(udn *udnv1.UserDefinedNetwork) {
	if len(udn.Name) > maxDNSLabelLen {
		klog.Warningf("ovn-kubernetes CoreDNS: UDN %s/%s name exceeds %d chars — skipping",
			udn.Namespace, udn.Name, maxDNSLabelLen)
		return
	}
	key := udnNADKey(udn.Namespace, udn.Name)
	c.udnNames[key] = struct{}{}
	c.udnSubnets[key] = extractUDNSubnets(&udn.Spec)
	klog.V(4).InfoS("ovn-kubernetes CoreDNS: indexed UDN", "key", key, "subnets", len(c.udnSubnets[key]))
}

// extractUDNSubnets pulls the pod CIDRs out of a UserDefinedNetworkSpec.
func extractUDNSubnets(spec *udnv1.UserDefinedNetworkSpec) []*net.IPNet {
	var out []*net.IPNet
	if spec.Layer3 != nil {
		for _, s := range spec.Layer3.Subnets {
			if _, n, err := net.ParseCIDR(string(s.CIDR)); err == nil {
				out = append(out, n)
			}
		}
	}
	if spec.Layer2 != nil {
		for _, cidr := range spec.Layer2.Subnets {
			if _, n, err := net.ParseCIDR(string(cidr)); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

// ---- CUDN event handlers ----

// OnCUDNAdd indexes a newly-created ClusterUserDefinedNetwork.
func (c *Cache) OnCUDNAdd(obj interface{}) {
	cudn, ok := obj.(*udnv1.ClusterUserDefinedNetwork)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addCUDNLocked(cudn)
}

// OnCUDNUpdate re-indexes a ClusterUserDefinedNetwork.
func (c *Cache) OnCUDNUpdate(_, newObj interface{}) {
	cudn, ok := newObj.(*udnv1.ClusterUserDefinedNetwork)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addCUDNLocked(cudn)
}

// OnCUDNDelete removes a ClusterUserDefinedNetwork from the index.
func (c *Cache) OnCUDNDelete(obj interface{}) {
	cudn, ok := obj.(*udnv1.ClusterUserDefinedNetwork)
	if !ok {
		if d, ok2 := obj.(cache.DeletedFinalStateUnknown); ok2 {
			cudn, ok = d.Obj.(*udnv1.ClusterUserDefinedNetwork)
			if !ok {
				return
			}
		} else {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cudnNames, cudn.Name)
	delete(c.cudnSubnets, cudn.Name)
}

func (c *Cache) addCUDNLocked(cudn *udnv1.ClusterUserDefinedNetwork) {
	if len(cudn.Name) > maxDNSLabelLen {
		klog.Warningf("ovn-kubernetes CoreDNS: CUDN %s name exceeds %d chars — skipping",
			cudn.Name, maxDNSLabelLen)
		return
	}
	c.cudnNames[cudn.Name] = struct{}{}
	c.cudnSubnets[cudn.Name] = extractNetworkSpecSubnets(&cudn.Spec.Network)
}

// extractNetworkSpecSubnets pulls the pod CIDRs out of a NetworkSpec.
func extractNetworkSpecSubnets(spec *udnv1.NetworkSpec) []*net.IPNet {
	var out []*net.IPNet
	if spec.Layer3 != nil {
		for _, s := range spec.Layer3.Subnets {
			if _, n, err := net.ParseCIDR(string(s.CIDR)); err == nil {
				out = append(out, n)
			}
		}
	}
	if spec.Layer2 != nil {
		for _, cidr := range spec.Layer2.Subnets {
			if _, n, err := net.ParseCIDR(string(cidr)); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

// ---- CNC event handlers ----

// OnCNCAdd registers the peer topology for a new ClusterNetworkConnect.
func (c *Cache) OnCNCAdd(obj interface{}) {
	cnc, ok := obj.(*cncv1.ClusterNetworkConnect)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateCNCLocked(cnc)
}

// OnCNCUpdate recomputes the peer topology after a CNC change.
func (c *Cache) OnCNCUpdate(_, newObj interface{}) {
	cnc, ok := newObj.(*cncv1.ClusterNetworkConnect)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeCNCLocked(cnc.Name)
	c.updateCNCLocked(cnc)
}

// OnCNCDelete retracts the peer topology for a deleted CNC.
func (c *Cache) OnCNCDelete(obj interface{}) {
	cnc, ok := obj.(*cncv1.ClusterNetworkConnect)
	if !ok {
		if d, ok2 := obj.(cache.DeletedFinalStateUnknown); ok2 {
			cnc, ok = d.Obj.(*cncv1.ClusterNetworkConnect)
			if !ok {
				return
			}
		} else {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeCNCLocked(cnc.Name)
}

func (c *Cache) updateCNCLocked(cnc *cncv1.ClusterNetworkConnect) {
	selected := c.resolveNetworkSelectorsLocked(cnc)
	if len(selected) < 2 {
		return
	}
	// All selected networks are direct peers of each other.
	for i, a := range selected {
		for j, b := range selected {
			if i != j {
				c.cncPeers[a] = appendUnique(c.cncPeers[a], b)
			}
		}
	}
	c.cncNetworks[cnc.Name] = selected
}

func (c *Cache) removeCNCLocked(cncName string) {
	selected, ok := c.cncNetworks[cncName]
	if !ok {
		return
	}
	for i, a := range selected {
		var others []string
		for j, b := range selected {
			if i != j {
				others = append(others, b)
			}
		}
		c.cncPeers[a] = removeAll(c.cncPeers[a], others)
		if len(c.cncPeers[a]) == 0 {
			delete(c.cncPeers, a)
		}
	}
	delete(c.cncNetworks, cncName)
}

// resolveNetworkSelectorsLocked returns the internal network keys matched by
// a CNC's NetworkSelectors, using the cached listers for CUDN label matching.
func (c *Cache) resolveNetworkSelectorsLocked(cnc *cncv1.ClusterNetworkConnect) []string {
	var keys []string
	for _, sel := range cnc.Spec.NetworkSelectors {
		switch sel.NetworkSelectionType {
		case "ClusterUserDefinedNetworks":
			if c.cudnLister == nil || sel.ClusterUserDefinedNetworkSelector == nil {
				continue
			}
			labelSel, err := labels.Parse(labelSelectorString(sel.ClusterUserDefinedNetworkSelector.NetworkSelector))
			if err != nil {
				klog.V(4).InfoS("ovn-kubernetes CoreDNS: invalid CUDN label selector in CNC",
					"cnc", cnc.Name, "err", err)
				continue
			}
			cudns, err := c.cudnLister.List(labelSel)
			if err != nil {
				continue
			}
			for _, cudn := range cudns {
				if _, known := c.cudnNames[cudn.Name]; known {
					keys = appendUnique(keys, internalNetKey("", cudn.Name, true))
				}
			}

		case "PrimaryUserDefinedNetworks":
			// Requires a namespace lister to fully evaluate namespaceSelector.
			// Conservative: include every known primary UDN.
			if c.udnLister == nil || sel.PrimaryUserDefinedNetworkSelector == nil {
				continue
			}
			udns, err := c.udnLister.List(labels.Everything())
			if err != nil {
				continue
			}
			for _, udn := range udns {
				key := udnNADKey(udn.Namespace, udn.Name)
				if _, known := c.udnNames[key]; known {
					keys = appendUnique(keys, key)
				}
			}
		}
	}
	return keys
}

// labelSelectorString converts a metav1.LabelSelector to a string suitable
// for labels.Parse.  Only matchLabels is supported; matchExpressions are
// ignored (with a conservative effect of matching everything).
func labelSelectorString(sel metav1.LabelSelector) string {
	var parts []string
	for k, v := range sel.MatchLabels {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

// ---- Read-only accessors ----

// PodByUDNIP returns the pod that holds the given UDN/CUDN IP.
func (c *Cache) PodByUDNIP(ip string) *object.Pod {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.udnIPIndex[ip]
}

// IsUDN reports whether "namespace/udn-name" is a known UDN.
func (c *Cache) IsUDN(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.udnNames[key]
	return ok
}

// IsCUDN reports whether name is a known CUDN.
func (c *Cache) IsCUDN(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.cudnNames[name]
	return ok
}

// NetworkKeyForIP returns the internal network key and whether it is a CUDN
// for the first UDN/CUDN subnet that contains ip.
// Returns ("", false, false) when no subnet matches.
func (c *Cache) NetworkKeyForIP(ip net.IP) (key string, isCUDN bool, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for k, subnets := range c.udnSubnets {
		for _, n := range subnets {
			if n.Contains(ip) {
				return k, false, true
			}
		}
	}
	for k, subnets := range c.cudnSubnets {
		for _, n := range subnets {
			if n.Contains(ip) {
				return k, true, true
			}
		}
	}
	return "", false, false
}

// PodsWithHostname returns pods with the given hostname, subdomain, and NAD key.
func (c *Cache) PodsWithHostname(hostname, subdomain, nadKey string) []*object.Pod {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*object.Pod
	for _, p := range c.pods {
		if p.Hostname == hostname && p.Subdomain == subdomain {
			if _, ok := p.UDNIPs[nadKey]; ok {
				out = append(out, p)
			}
		}
	}
	return out
}

// SearchPathPeers returns the direct peer network keys for a given internal
// network key, as established by ClusterNetworkConnect objects.
func (c *Cache) SearchPathPeers(key string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cncPeers[key]
}

// InternalKeysForPod returns the internal network keys for every UDN/CUDN
// network a pod is attached to.
func (c *Cache) InternalKeysForPod(p *object.Pod) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var keys []string
	for nadKey := range p.UDNIPs {
		if k, _ := c.internalKeyForNAD(nadKey); k != "" {
			keys = appendUnique(keys, k)
		}
	}
	return keys
}

// CanQuery reports whether a DNS query from sourceIP may resolve records on
// targetNetKey, which is always a UDN or CUDN internal key
// ("ns/name" for UDN, "cudn:name" for CUDN).
//
// Decision table:
//
//   sourceUDN = nil  (default-network pod, hostNetwork pod, or unknown)
//              → BLOCK: a non-UDN source must not enumerate UDN/CUDN addresses.
//
//   sourceUDN != nil
//     sourceUDN == targetNetKey                → ALLOW (same network)
//     targetNetKey in CNC-direct-peers(src)    → ALLOW (data-plane path exists)
//     otherwise                                → BLOCK
//
// Note: the "both UDN = nil → fall through to kubernetes" case is handled
// one layer up: parseQuery returns queryUnknown for non-UDN names, causing
// plugin.NextOrFailure before CanQuery is ever called.
func (c *Cache) CanQuery(sourceIP, targetNetKey string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sourceUDNs := c.sourceUDNsLocked(sourceIP)
	if len(sourceUDNs) == 0 {
		// sourceUDN is nil: default-network pod, hostNetwork pod, or a pod
		// whose OVN-K annotation has not arrived yet.
		// All of these are blocked from resolving UDN/CUDN records.
		// UDN pods do carry an infrastructure-locked default-network interface
		// for kubelet health checks, but their DNS queries originate from
		// their UDN primary IP and are found in udnIPIndex correctly.
		return false
	}

	for _, srcNetKey := range sourceUDNs {
		if srcNetKey == targetNetKey {
			return true
		}
		for _, peer := range c.cncPeers[srcNetKey] {
			if peer == targetNetKey {
				return true
			}
		}
	}
	return false
}

// sourceUDNsLocked resolves the internal network key(s) for the pod that owns
// sourceIP. Returns nil when the IP is not in any UDN/CUDN (default-network
// pod, hostNetwork pod, or unknown). Must be called with c.mu held for read.
func (c *Cache) sourceUDNsLocked(sourceIP string) []string {
	srcPod := c.udnIPIndex[sourceIP]
	if srcPod == nil {
		return nil
	}
	var keys []string
	for nadKey := range srcPod.UDNIPs {
		if _, ok := c.udnNames[nadKey]; ok {
			keys = appendUnique(keys, nadKey)
		} else if parts := strings.SplitN(nadKey, "/", 2); len(parts) == 2 {
			if _, ok := c.cudnNames[parts[1]]; ok {
				keys = appendUnique(keys, networkKeyPrefixCUDN+parts[1])
			}
		}
	}
	return keys
}

// isOVNInternalCIDR returns true for subnets that OVN-K uses internally
// (join subnet ~100.64.x.x, transit subnet ~100.88.x.x, etc.) which are
// outside normal pod/service/node IP ranges.
func isOVNInternalCIDR(cidr *net.IPNet) bool {
	ip := cidr.IP
	// Private ranges used by pods, services, and nodes — not OVN-internal.
	for _, privateRange := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, private, _ := net.ParseCIDR(privateRange)
		if private.Contains(ip) {
			return false
		}
	}
	// Link-local (169.254.x.x masquerade subnet) counts as OVN-internal too.
	if ip[0] == 169 && ip[1] == 254 {
		return true
	}
	// Any other non-private unicast (e.g. 100.64.x.x, 100.88.x.x) is
	// assumed to be an OVN-internal allocation.
	return ip.IsGlobalUnicast()
}

// addOVNInternalCIDRLocked records a new OVN-internal CIDR if not already
// present. Must be called with c.mu held for write.
func (c *Cache) addOVNInternalCIDRLocked(cidr *net.IPNet) {
	for _, existing := range c.ovnInternalCIDRs {
		if existing.String() == cidr.String() {
			return
		}
	}
	klog.V(4).InfoS("ovn-kubernetes CoreDNS: discovered OVN-internal subnet",
		"cidr", cidr.String())
	c.ovnInternalCIDRs = append(c.ovnInternalCIDRs, cidr)
}

// isOVNInternalSourceLocked reports whether sourceIP falls inside any of the
// OVN-internal subnets discovered from pod annotations. Must be called with
// c.mu held for read.
func (c *Cache) isOVNInternalSourceLocked(sourceIP string) bool {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return false
	}
	for _, cidr := range c.ovnInternalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// SetListers stores the listers needed for CNC NetworkSelector resolution.
func (c *Cache) SetListers(
	udnLister udnlisters.UserDefinedNetworkLister,
	cudnLister udnlisters.ClusterUserDefinedNetworkLister,
	cncLister cnclisters.ClusterNetworkConnectLister,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.udnLister = udnLister
	c.cudnLister = cudnLister
	c.cncLister = cncLister
}

// ---- Internal helpers ----

// internalKeyForNAD converts a NAD key ("ns/name") to an internal network key
// by checking the UDN and CUDN registries.  Returns ("", false) when the NAD
// does not correspond to any known UDN/CUDN.
func (c *Cache) internalKeyForNAD(nadKey string) (string, bool) {
	if _, ok := c.udnNames[nadKey]; ok {
		return nadKey, false // UDN: internal key == NAD key
	}
	if parts := strings.SplitN(nadKey, "/", 2); len(parts) == 2 {
		if _, ok := c.cudnNames[parts[1]]; ok {
			return networkKeyPrefixCUDN + parts[1], true // CUDN
		}
	}
	return "", false
}

// nadKeyToSearchEntry converts an internal network key to a DNS search-path
// label in the form used by autopath.
//   - UDN  "ns/name"    → "name.ns.svc.<zone>"
//   - CUDN "cudn:name"  → "name.svc.<zone>"
func nadKeyToSearchEntry(key, zone string) string {
	if strings.HasPrefix(key, networkKeyPrefixCUDN) {
		name := strings.TrimPrefix(key, networkKeyPrefixCUDN)
		return fmt.Sprintf("%s.svc.%s", name, zone)
	}
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return fmt.Sprintf("%s.%s.svc.%s", parts[1], parts[0], zone)
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func removeAll(slice []string, toRemove []string) []string {
	out := slice[:0]
	for _, v := range slice {
		keep := true
		for _, r := range toRemove {
			if v == r {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, v)
		}
	}
	return out
}
