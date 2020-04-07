package node

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
)

// LoadBalancerHealthChecker responds to add/delete endpoint/service events
// to ensure that the service loadbalancer is healthy
type LoadBalancerHealthChecker interface {
	AddService(svc *kapi.Service)
	DeleteService(svc *kapi.Service)
	AddEndpoints(ep *kapi.Endpoints)
	DeleteEndpoints(ep *kapi.Endpoints)
}

type loadBalancerHealthChecker struct {
	nodeName  string
	server    healthcheck.Server
	services  map[ktypes.NamespacedName]uint16
	endpoints map[ktypes.NamespacedName]int
}

// NewLoadBalancerHealthChecker returns a new load balancer health checker
func NewLoadBalancerHealthChecker(nodeName string) LoadBalancerHealthChecker {
	return &loadBalancerHealthChecker{
		nodeName:  nodeName,
		server:    healthcheck.NewServer(nodeName, nil, nil, nil),
		services:  make(map[ktypes.NamespacedName]uint16),
		endpoints: make(map[ktypes.NamespacedName]int),
	}
}

type dummyLoadBalancerHealthChecker struct{}

func (d dummyLoadBalancerHealthChecker) AddService(svc *kapi.Service)       { return }
func (d dummyLoadBalancerHealthChecker) DeleteService(svc *kapi.Service)    { return }
func (d dummyLoadBalancerHealthChecker) AddEndpoints(ep *kapi.Endpoints)    { return }
func (d dummyLoadBalancerHealthChecker) DeleteEndpoints(ep *kapi.Endpoints) { return }

// DummyLoadBalancerHealthChecker returns a noop implementation of the LoadBalancerHealthChecker interface
func DummyLoadBalancerHealthChecker() LoadBalancerHealthChecker {
	return &dummyLoadBalancerHealthChecker{}
}

// AddService handles the add service event
func (l *loadBalancerHealthChecker) AddService(svc *kapi.Service) {
	if svc.Spec.HealthCheckNodePort != 0 {
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		l.services[name] = uint16(svc.Spec.HealthCheckNodePort)
		_ = l.server.SyncServices(l.services)
	}
}

// DeleteService handles the delete service event
func (l *loadBalancerHealthChecker) DeleteService(svc *kapi.Service) {
	if svc.Spec.HealthCheckNodePort != 0 {
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		delete(l.services, name)
		delete(l.endpoints, name)
		_ = l.server.SyncServices(l.services)
	}
}

// AddEndpoints handles the add endpoints event
func (l *loadBalancerHealthChecker) AddEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	if _, exists := l.services[name]; exists {
		l.endpoints[name] = countLocalEndpoints(ep, l.nodeName)
		_ = l.server.SyncEndpoints(l.endpoints)
	}
}

// DeleteEndpoints handles the delete endpoints event
func (l *loadBalancerHealthChecker) DeleteEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	delete(l.endpoints, name)
	_ = l.server.SyncEndpoints(l.endpoints)
}

func countLocalEndpoints(ep *kapi.Endpoints, nodeName string) int {
	num := 0
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Addresses {
			addr := &ss.Addresses[i]
			if addr.NodeName != nil && *addr.NodeName == nodeName {
				num++
			}
		}
	}
	return num
}

// check for OVS internal ports without any ofport assigned, they are stale ports that must be deleted
func checkForStaleOVSInterfaces(stopChan <-chan struct{}) {
	for {
		select {
		case <-time.After(60 * time.Second):
			stdout, _, err := util.RunOVSVsctl("--data=bare", "--no-headings", "--columns=name", "find",
				"interface", "ofport=-1")
			if err != nil {
				klog.Errorf("failed to list OVS interfaces with ofport set to -1")
				continue
			}
			if len(stdout) == 0 {
				continue
			}
			values := strings.Split(stdout, "\n\n")
			for _, val := range values {
				klog.Warningf("found stale interface %s, so deleting it", val)
				_, stderr, err := util.RunOVSVsctl("--if-exists", "--with-iface", "del-port", val)
				if err != nil {
					klog.Errorf("failed to delete OVS port/interface %s: stderr: %s (%v)",
						val, stderr, err)
				}
			}
		case <-stopChan:
			return
		}
	}
}

// checkDefaultOpenFlow checks for the existence of default OpenFlow rules and
// exits if the output is not as expected
func checkDefaultConntrackRules(gwBridge string, nFlows int, stopChan <-chan struct{}) {
	flowCount := fmt.Sprintf("flow_count=%d", nFlows)
	for {
		select {
		case <-time.After(30 * time.Second):
			out, _, err := util.RunOVSOfctl("dump-aggregate", gwBridge,
				fmt.Sprintf("cookie=%s/-1", defaultOpenFlowCookie))
			if err != nil {
				klog.Errorf("failed to dump aggregate statistics of the default OpenFlow rules: %v", err)
				continue
			}

			if !strings.Contains(out, flowCount) {
				klog.Errorf("fatal error: unexpected default OpenFlows count, expect %d output: %v\n",
					nFlows, out)
				os.Exit(1)
			}
		case <-stopChan:
			return
		}
	}
}
