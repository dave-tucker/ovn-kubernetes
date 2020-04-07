package ovn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"k8s.io/client-go/tools/cache"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/allocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
)

// ServiceVIPKey is used for looking up service namespace information for a
// particular load balancer
type ServiceVIPKey struct {
	// Load balancer VIP in the form "ip:port"
	vip string
	// Protocol used by the load balancer
	protocol kapi.Protocol
}

// loadBalancerConf contains the OVN based config for a LB
type loadBalancerConf struct {
	// List of endpoints as configured in OVN, ip:port
	endpoints []string
	// ACL configured for Rejecting access to the LB
	rejectACL string
}

// Controller structure is the object which holds the controls for starting
// and reacting upon the watched resources (e.g. pods, endpoints)
type Controller struct {
	kube     kube.Interface
	stopChan <-chan struct{}

	masterSubnetAllocator *allocator.SubnetAllocator
	joinSubnetAllocator   *allocator.SubnetAllocator

	TCPLoadBalancerUUID  string
	UDPLoadBalancerUUID  string
	SCTPLoadBalancerUUID string
	SCTPSupport          bool

	// For TCP, UDP, and SCTP type traffic, cache OVN load-balancers used for the
	// cluster's east-west traffic.
	loadbalancerClusterCache map[kapi.Protocol]string

	// For TCP and UDP type traffice, cache OVN load balancer that exists on the
	// default gateway
	loadbalancerGWCache map[kapi.Protocol]string
	defGatewayRouter    string

	// A cache of all logical switches seen by the watcher and their subnets
	logicalSwitchCache map[string]*net.IPNet

	// A cache of all logical ports known to the controller
	logicalPortCache *portCache

	// For each namespace, a map from pod IP address to logical port name
	// for all pods in that namespace.
	namespaceAddressSet map[string]map[string]string

	// For each namespace, a lock to protect critical regions
	namespaceMutex map[string]*sync.Mutex

	// Need to make calls to namespaceMutex also thread-safe
	namespaceMutexMutex sync.Mutex

	// A mutex for logicalSwitchCache which holds logicalSwitch information
	lsMutex *sync.Mutex

	// Per namespace multicast enabled?
	multicastEnabled map[string]bool

	// Supports multicast?
	multicastSupport bool

	// Map of load balancers to service namespace
	serviceVIPToName map[ServiceVIPKey]types.NamespacedName

	serviceVIPToNameLock sync.Mutex

	// Map of load balancers, each containing a map of VIP to OVN LB Config
	serviceLBMap map[string]map[string]*loadBalancerConf

	serviceLBLock sync.Mutex

	// event recorder used to post events to k8s
	recorder record.EventRecorder

	gatewaysFailed sync.Map
	mgmtPortFailed sync.Map
	retryPods      sync.Map

	// eventHandlers
	nodeInformer          informer.EventHandler
	podInformer           informer.EventHandler
	servicesInformer      informer.EventHandler
	endpointsInformer     informer.EventHandler
	namespacesInformer    informer.EventHandler
	networkPolicyInformer informer.EventHandler
}

const (
	// TCP is the constant string for the string "TCP"
	TCP = "TCP"

	// UDP is the constant string for the string "UDP"
	UDP = "UDP"

	// SCTP is the constant string for the string "SCTP"
	SCTP = "SCTP"
)

// NewOvnController creates a new OVN controller for creating logical network
// infrastructure and policy
func NewOvnController(
	kubeClient kubernetes.Interface,
	nodeInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
	servicesInformer cache.SharedIndexInformer,
	endpointsInformer cache.SharedIndexInformer,
	namespacesInformer cache.SharedIndexInformer,
	networkPolicyInformer cache.SharedIndexInformer,
	stopChan <-chan struct{},
) *Controller {
	c := &Controller{
		kube:                     &kube.Kube{KClient: kubeClient},
		stopChan:                 stopChan,
		masterSubnetAllocator:    allocator.NewSubnetAllocator(),
		logicalSwitchCache:       make(map[string]*net.IPNet),
		joinSubnetAllocator:      allocator.NewSubnetAllocator(),
		logicalPortCache:         newPortCache(stopChan),
		namespaceAddressSet:      make(map[string]map[string]string),
		namespaceMutex:           make(map[string]*sync.Mutex),
		namespaceMutexMutex:      sync.Mutex{},
		lsMutex:                  &sync.Mutex{},
		loadbalancerClusterCache: make(map[kapi.Protocol]string),
		loadbalancerGWCache:      make(map[kapi.Protocol]string),
		multicastEnabled:         make(map[string]bool),
		multicastSupport:         config.EnableMulticast,
		serviceVIPToName:         make(map[ServiceVIPKey]types.NamespacedName),
		serviceVIPToNameLock:     sync.Mutex{},
		serviceLBMap:             make(map[string]map[string]*loadBalancerConf),
		serviceLBLock:            sync.Mutex{},
		recorder:                 util.EventRecorder(kubeClient),
		gatewaysFailed:           sync.Map{},
		mgmtPortFailed:           sync.Map{},
		retryPods:                sync.Map{},
	}

	c.nodeInformer = informer.NewDefaultEventHandler(
		"node",
		nodeInformer,
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("obj is not a node")
			}
			return c.addNode(node)
		},
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("obj is not a node")
			}
			return c.deleteNode(node)
		},
	)

	c.podInformer = informer.NewDefaultEventHandler(
		"pod",
		podInformer,
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("obj is not a pod")
			}
			// TODO: Parallel dispatch
			return c.addPod(pod)
		},
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("obj is not a pod")
			}
			// TODO: Parallel dispatch
			return c.deletePod(pod)
		},
	)

	c.servicesInformer = informer.NewDefaultEventHandler(
		"service",
		servicesInformer,
		func(obj interface{}) error {
			service, ok := obj.(*kapi.Service)
			if !ok {
				return fmt.Errorf("obj is not a service")
			}
			return c.addService(service)
		},
		func(obj interface{}) error {
			service, ok := obj.(*kapi.Service)
			if !ok {
				return fmt.Errorf("obj is not a service")
			}
			return c.deleteService(service)
		},
	)

	c.endpointsInformer = informer.NewDefaultEventHandler(
		"endpoints",
		endpointsInformer,
		func(obj interface{}) error {
			endpoint, ok := obj.(*kapi.Endpoints)
			if !ok {
				return fmt.Errorf("obj is not a endpoint")
			}
			return c.addEndpoints(endpoint)
		},
		func(obj interface{}) error {
			endpoint, ok := obj.(*kapi.Endpoints)
			if !ok {
				return fmt.Errorf("obj is not a endpoint")
			}
			return c.deleteEndpoints(endpoint)
		},
	)

	c.namespacesInformer = informer.NewDefaultEventHandler(
		"namespaces",
		namespacesInformer,
		func(obj interface{}) error {
			namespace, ok := obj.(*kapi.Namespace)
			if !ok {
				return fmt.Errorf("obj is not a namespace")
			}
			return c.addNamespace(namespace)
		},
		func(obj interface{}) error {
			namespace, ok := obj.(*kapi.Namespace)
			if !ok {
				return fmt.Errorf("obj is not a namespace")
			}
			return c.deleteNamespace(namespace)
		},
	)

	c.networkPolicyInformer = informer.NewDefaultEventHandler(
		"network policy",
		networkPolicyInformer,
		func(obj interface{}) error {
			networkpolicy, ok := obj.(*knet.NetworkPolicy)
			if !ok {
				return fmt.Errorf("obj is not a networkpolicy")
			}
			return c.addNetworkPolicy(networkpolicy)
		},
		func(obj interface{}) error {
			networkpolicy, ok := obj.(*knet.NetworkPolicy)
			if !ok {
				return fmt.Errorf("obj is not a networkpolicy")
			}
			return c.deleteNetworkPolicy(networkpolicy)
		},
	)

	return c
}

// Run starts the actual watching.
func (oc *Controller) Run(stopCh <-chan struct{}) {
	oc.syncPeriodic(stopCh)
	// WatchNodes must be started first so that its initial Add will
	// create all node logical switches, which other watches may depend on.
	// https://github.com/ovn-org/ovn-kubernetes/pull/859s
	go oc.nodeInformer.Run(informer.DefaultNodeInformerThreadiness, stopCh)
	go oc.podInformer.Run(informer.DefaultInformerThreadiness, stopCh)
	go oc.servicesInformer.Run(informer.DefaultInformerThreadiness, stopCh)
	go oc.endpointsInformer.Run(informer.DefaultInformerThreadiness, stopCh)
	go oc.namespacesInformer.Run(informer.DefaultInformerThreadiness, stopCh)
	go oc.networkPolicyInformer.Run(informer.DefaultInformerThreadiness, stopCh)

	if config.Kubernetes.OVNEmptyLbEvents {
		go oc.ovnControllerEventChecker()
	}
	<-stopCh
}

type eventRecord struct {
	Data     [][]interface{} `json:"Data"`
	Headings []string        `json:"Headings"`
}

type emptyLBBackendEvent struct {
	vip      string
	protocol kapi.Protocol
	uuid     string
}

func extractEmptyLBBackendsEvents(out []byte) ([]emptyLBBackendEvent, error) {
	events := make([]emptyLBBackendEvent, 0, 4)

	var f eventRecord
	err := json.Unmarshal(out, &f)
	if err != nil {
		return events, err
	}
	if len(f.Data) == 0 {
		return events, nil
	}

	var eventInfoIndex int
	var eventTypeIndex int
	var uuidIndex int
	for idx, val := range f.Headings {
		switch val {
		case "event_info":
			eventInfoIndex = idx
		case "event_type":
			eventTypeIndex = idx
		case "_uuid":
			uuidIndex = idx
		}
	}

	for _, val := range f.Data {
		if len(val) <= eventTypeIndex {
			return events, errors.New("Mismatched Data and Headings in controller event")
		}
		if val[eventTypeIndex] != "empty_lb_backends" {
			continue
		}

		uuidArray, ok := val[uuidIndex].([]interface{})
		if !ok {
			return events, errors.New("Unexpected '_uuid' data in controller event")
		}
		if len(uuidArray) < 2 {
			return events, errors.New("Malformed UUID presented in controller event")
		}
		uuid, ok := uuidArray[1].(string)
		if !ok {
			return events, errors.New("Failed to parse UUID in controller event")
		}

		// Unpack the data. There's probably a better way to do this.
		info, ok := val[eventInfoIndex].([]interface{})
		if !ok {
			return events, errors.New("Unexpected 'event_info' data in controller event")
		}
		if len(info) < 2 {
			return events, errors.New("Malformed event_info in controller event")
		}
		eventMap, ok := info[1].([]interface{})
		if !ok {
			return events, errors.New("'event_info' data is not the expected type")
		}

		var vip string
		var protocol kapi.Protocol
		for _, x := range eventMap {
			tuple, ok := x.([]interface{})
			if !ok {
				return events, errors.New("event map item failed to parse")
			}
			if len(tuple) < 2 {
				return events, errors.New("event map contains malformed data")
			}
			switch tuple[0] {
			case "vip":
				vip, ok = tuple[1].(string)
				if !ok {
					return events, errors.New("Failed to parse vip in controller event")
				}
			case "protocol":
				prot, ok := tuple[1].(string)
				if !ok {
					return events, errors.New("Failed to parse protocol in controller event")
				}
				if prot == "udp" {
					protocol = kapi.ProtocolUDP
				} else if prot == "sctp" {
					protocol = kapi.ProtocolSCTP
				} else {
					protocol = kapi.ProtocolTCP
				}
			}
		}
		events = append(events, emptyLBBackendEvent{vip, protocol, uuid})
	}

	return events, nil
}

// syncPeriodic adds a goroutine that periodically does some work
// right now there is only one ticker registered
// for syncNodesPeriodic which deletes chassis records from the sbdb
// every 5 minutes
func (oc *Controller) syncPeriodic(stopChan <-chan struct{}) {
	go func() {
		nodeSyncTicker := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-nodeSyncTicker.C:
				oc.syncNodesPeriodic()
			case <-stopChan:
				return
			}
		}
	}()

}

func (oc *Controller) ovnControllerEventChecker() {
	ticker := time.NewTicker(5 * time.Second)

	_, _, err := util.RunOVNNbctl("set", "nb_global", ".", "options:controller_event=true")
	if err != nil {
		klog.Error("Unable to enable controller events. Unidling not possible")
		return
	}

	for {
		select {
		case <-ticker.C:
			out, _, err := util.RunOVNSbctl("--format=json", "list", "controller_event")
			if err != nil {
				continue
			}

			events, err := extractEmptyLBBackendsEvents([]byte(out))
			if err != nil || len(events) == 0 {
				continue
			}

			for _, event := range events {
				_, _, err := util.RunOVNSbctl("destroy", "controller_event", event.uuid)
				if err != nil {
					// Don't unidle until we are able to remove the controller event
					klog.Errorf("Unable to remove controller event %s", event.uuid)
					continue
				}
				if serviceName, ok := oc.GetServiceVIPToName(event.vip, event.protocol); ok {
					serviceRef := kapi.ObjectReference{
						Kind:      "Service",
						Namespace: serviceName.Namespace,
						Name:      serviceName.Name,
					}
					klog.V(5).Infof("Sending a NeedPods event for service %s in namespace %s.", serviceName.Name, serviceName.Namespace)
					oc.recorder.Eventf(&serviceRef, kapi.EventTypeNormal, "NeedPods", "The service %s needs pods", serviceName.Name)
				}
			}
		case <-oc.stopChan:
			return
		}
	}
}

func podWantsNetwork(pod *kapi.Pod) bool {
	return !pod.Spec.HostNetwork
}

func podScheduled(pod *kapi.Pod) bool {
	return pod.Spec.NodeName != ""
}

func (oc *Controller) addPod(pod *kapi.Pod) error {
	if !podWantsNetwork(pod) {
		return nil
	}

	if podScheduled(pod) {
		if err := oc.addLogicalPort(pod); err != nil {
			klog.Errorf(err.Error())
			oc.retryPods.Store(pod.UID, true)
		}
	} else {
		// Handle unscheduled pods later in UpdateFunc
		oc.retryPods.Store(pod.UID, true)
	}
	return nil
}

// DeletePod responds to the deletePod event
func (oc *Controller) deletePod(pod *kapi.Pod) error {
	oc.deleteLogicalPort(pod)
	oc.retryPods.Delete(pod.UID)
	return nil
}

func (oc *Controller) addService(service *kapi.Service) error {
	err := oc.createService(service)
	if err != nil {
		klog.Errorf("Error in adding service: %v", err)
	}
	//TODO: Merge this with Add
	/*
		err := oc.updateService(svcOld, svcNew)
		if err != nil {
			klog.Errorf("Error while updating service: %v", err)
		}
	*/
	return nil
}

/* TODO: ADD LOGIC IN TO ADD ENPOINTS FN
epNew := new.(*kapi.Endpoints)
epOld := old.(*kapi.Endpoints)
if reflect.DeepEqual(epNew.Subsets, epOld.Subsets) {
	return
}
if len(epNew.Subsets) == 0 {
	err := oc.deleteEndpoints(epNew)
	if err != nil {
		klog.Errorf("Error in deleting endpoints - %v", err)
	}
} else {
	err := oc.AddEndpoints(epNew)
	if err != nil {
		klog.Errorf("Error in modifying endpoints: %v", err)
	}
}
*/

/* TODO: ADD LOGIC TO ADD NETWORK POLICY FN
oldPolicy := old.(*kapisnetworking.NetworkPolicy)
newPolicy := newer.(*kapisnetworking.NetworkPolicy)
if !reflect.DeepEqual(oldPolicy, newPolicy) {
	oc.deleteNetworkPolicy(oldPolicy)
	oc.addNetworkPolicy(newPolicy)
}
*/
func (oc *Controller) syncNodeGateway(node *kapi.Node, subnet *net.IPNet) error {
	l3GatewayConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		return err
	}

	if subnet == nil {
		subnet, _ = util.ParseNodeHostSubnetAnnotation(node)
	}
	if l3GatewayConfig.Mode == config.GatewayModeDisabled {
		if err := util.GatewayCleanup(node.Name, subnet); err != nil {
			return fmt.Errorf("error cleaning up gateway for node %s: %v", node.Name, err)
		}
	} else if subnet != nil {
		if err := oc.syncGatewayLogicalNetwork(node, l3GatewayConfig, subnet.String()); err != nil {
			return fmt.Errorf("error creating gateway for node %s: %v", node.Name, err)
		}
	}
	return nil
}

func (oc *Controller) addNode(node *kapi.Node) error {
	if noHostSubnet := noHostSubnet(node); noHostSubnet {
		oc.lsMutex.Lock()
		defer oc.lsMutex.Unlock()
		//setting the value to nil in the cache means it was not assigned a hostSubnet by ovn-kube
		oc.logicalSwitchCache[node.Name] = nil
		return nil
	}

	klog.V(5).Infof("Added event for Node %q", node.Name)
	hostSubnet, err := oc.doAddNode(node)
	if err != nil {
		klog.Errorf("error creating subnet for node %s: %v", node.Name, err)
		return nil
	}

	err = oc.syncNodeManagementPort(node, hostSubnet)
	if err != nil {
		klog.Errorf("error creating management port for node %s: %v", node.Name, err)
		oc.mgmtPortFailed.Store(node.Name, true)
	}

	if err := oc.syncNodeGateway(node, hostSubnet); err != nil {
		klog.Errorf(err.Error())
		oc.gatewaysFailed.Store(node.Name, true)
	}
	/* TODO: Merge with Add fn
	UpdateFunc: func(old, new interface{}) {
			oldNode := old.(*kapi.Node)
			node := new.(*kapi.Node)

			shouldUpdate, err := shouldUpdate(node, oldNode)
			if err != nil {
				klog.Errorf(err.Error())
			}
			if !shouldUpdate {
				// the hostsubnet is not assigned by ovn-kubernetes
				return
			}

			klog.V(5).Infof("Updated event for Node %q", node.Name)

			_, failed := mgmtPortFailed.Load(node.Name)
			if failed || macAddressChanged(oldNode, node) {
				err := oc.syncNodeManagementPort(node, nil)
				if err != nil {
					klog.Errorf("error updating management port for node %s: %v", node.Name, err)
					mgmtPortFailed.Store(node.Name, true)
				} else {
					mgmtPortFailed.Delete(node.Name)
				}
			}

			oc.clearInitialNodeNetworkUnavailableCondition(oldNode, node)

			_, failed = gatewaysFailed.Load(node.Name)
			if failed || gatewayChanged(oldNode, node) {
				err := oc.syncNodeGateway(node, nil)
				if err != nil {
					klog.Errorf(err.Error())
					gatewaysFailed.Store(node.Name, true)
				} else {
					gatewaysFailed.Delete(node.Name)
				}
			}
		},
	*/
	return nil
}

// DeleteNode handles the node delete event
func (oc *Controller) deleteNode(node *kapi.Node) error {
	klog.V(5).Infof("Delete event for Node %q. Removing the node from "+
		"various caches", node.Name)

	nodeSubnet, _ := util.ParseNodeHostSubnetAnnotation(node)
	joinSubnet, _ := util.ParseNodeJoinSubnetAnnotation(node)
	err := oc.doDeleteNode(node.Name, nodeSubnet, joinSubnet)
	if err != nil {
		klog.Error(err)
	}
	oc.lsMutex.Lock()
	delete(oc.logicalSwitchCache, node.Name)
	oc.lsMutex.Unlock()
	oc.mgmtPortFailed.Delete(node.Name)
	oc.gatewaysFailed.Delete(node.Name)
	// If this node was serving the external IP load balancer for services, migrate to a new node
	if oc.defGatewayRouter == util.GWRouterPrefix+node.Name {
		delete(oc.loadbalancerGWCache, kapi.ProtocolTCP)
		delete(oc.loadbalancerGWCache, kapi.ProtocolUDP)
		delete(oc.loadbalancerGWCache, kapi.ProtocolSCTP)
		oc.defGatewayRouter = ""
		oc.updateExternalIPsLB()

	}
	return nil
}

// AddServiceVIPToName associates a k8s service name with a load balancer VIP
func (oc *Controller) AddServiceVIPToName(vip string, protocol kapi.Protocol, namespace, name string) {
	oc.serviceVIPToNameLock.Lock()
	defer oc.serviceVIPToNameLock.Unlock()
	oc.serviceVIPToName[ServiceVIPKey{vip, protocol}] = types.NamespacedName{Namespace: namespace, Name: name}
}

// GetServiceVIPToName retrieves the associated k8s service name for a load balancer VIP
func (oc *Controller) GetServiceVIPToName(vip string, protocol kapi.Protocol) (types.NamespacedName, bool) {
	oc.serviceVIPToNameLock.Lock()
	defer oc.serviceVIPToNameLock.Unlock()
	namespace, ok := oc.serviceVIPToName[ServiceVIPKey{vip, protocol}]
	return namespace, ok
}

// setServiceLBToACL associates an empty load balancer with its associated ACL reject rule
func (oc *Controller) setServiceACLToLB(lb, vip, acl string) {
	if _, ok := oc.serviceLBMap[lb]; !ok {
		oc.serviceLBMap[lb] = make(map[string]*loadBalancerConf)
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{rejectACL: acl}
		return
	}
	if _, ok := oc.serviceLBMap[lb][vip]; !ok {
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{rejectACL: acl}
		return
	}
	oc.serviceLBMap[lb][vip].rejectACL = acl
}

// setServiceEndpointsToLB associates a load balancer with endpoints
func (oc *Controller) setServiceEndpointsToLB(lb, vip string, eps []string) {
	if _, ok := oc.serviceLBMap[lb]; !ok {
		oc.serviceLBMap[lb] = make(map[string]*loadBalancerConf)
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{endpoints: eps}
		return
	}
	if _, ok := oc.serviceLBMap[lb][vip]; !ok {
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{endpoints: eps}
		return
	}
	oc.serviceLBMap[lb][vip].endpoints = eps
}

// getServiceLBInfo returns the reject ACL and whether the number of endpoints for the service is greater than zero
func (oc *Controller) getServiceLBInfo(lb, vip string) (string, bool) {
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	conf, ok := oc.serviceLBMap[lb][vip]
	if !ok {
		conf = &loadBalancerConf{}
	}
	return conf.rejectACL, len(conf.endpoints) > 0
}

// getAllACLsForServiceLB retrieves all of the ACLs for a given load balancer
func (oc *Controller) getAllACLsForServiceLB(lb string) []string {
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	confMap, ok := oc.serviceLBMap[lb]
	if !ok {
		return nil
	}
	var acls []string
	for _, v := range confMap {
		if len(v.rejectACL) > 0 {
			acls = append(acls, v.rejectACL)
		}
	}
	return acls
}

// removeServiceLB removes the entire LB entry for a VIP
func (oc *Controller) removeServiceLB(lb, vip string) {
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	delete(oc.serviceLBMap[lb], vip)
}

// removeServiceACL removes a specific ACL associated with a load balancer and ip:port
func (oc *Controller) removeServiceACL(lb, vip string) {
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	if _, ok := oc.serviceLBMap[lb][vip]; ok {
		oc.serviceLBMap[lb][vip].rejectACL = ""
	}
}

// removeServiceEndpoints removes endpoints associated with a load balancer and ip:port
func (oc *Controller) removeServiceEndpoints(lb, vip string) {
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	if _, ok := oc.serviceLBMap[lb][vip]; ok {
		oc.serviceLBMap[lb][vip].endpoints = []string{}
	}
}

// gatewayChanged() compares old annotations to new and returns true if something has changed.
func gatewayChanged(oldNode, newNode *kapi.Node) bool {
	oldL3GatewayConfig, _ := util.ParseNodeL3GatewayAnnotation(oldNode)
	l3GatewayConfig, _ := util.ParseNodeL3GatewayAnnotation(newNode)

	if oldL3GatewayConfig == nil && l3GatewayConfig == nil {
		return false
	}

	return !reflect.DeepEqual(oldL3GatewayConfig, l3GatewayConfig)
}

// macAddressChanged() compares old annotations to new and returns true if something has changed.
func macAddressChanged(oldNode, node *kapi.Node) bool {
	oldMacAddress, _ := util.ParseNodeManagementPortMacAddr(oldNode)
	macAddress, _ := util.ParseNodeManagementPortMacAddr(node)
	return oldMacAddress != macAddress
}

// noHostSubnet() compares the no-hostsubenet-nodes flag with node labels to see if the node is manageing its
// own network.
func noHostSubnet(node *kapi.Node) bool {
	if config.Kubernetes.NoHostSubnetNodes == nil {
		return false
	}

	nodeSelector, _ := metav1.LabelSelectorAsSelector(config.Kubernetes.NoHostSubnetNodes)
	return nodeSelector.Matches(labels.Set(node.Labels))
}

// shouldUpdate() determines if the ovn-kubernetes plugin should update the state of the node.
// ovn-kube should not perform an update if it does not assign a hostsubnet, or if you want to change
// whether or not ovn-kubernetes assigns a hostsubnet
func shouldUpdate(node, oldNode *kapi.Node) (bool, error) {
	newNoHostSubnet := noHostSubnet(node)
	oldNoHostSubnet := noHostSubnet(oldNode)

	if oldNoHostSubnet && newNoHostSubnet {
		return false, nil
	} else if oldNoHostSubnet && !newNoHostSubnet {
		return false, fmt.Errorf("error updating node %s, cannot remove assigned hostsubnet, please delete node and recreate", node.Name)
	} else if !oldNoHostSubnet && newNoHostSubnet {
		return false, fmt.Errorf("error updating node %s, cannot assign a hostsubnet to already created node, please delete node and recreate", node.Name)
	}

	return true, nil
}
