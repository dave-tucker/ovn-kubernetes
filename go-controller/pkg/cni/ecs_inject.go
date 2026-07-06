// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cni

// ECSInjector is the interface satisfied by ecs.Manager.
// Defined here so that go-controller/pkg/cni does not need to import the
// cilium/ebpf dependency at build time — the concrete implementation is
// supplied by the caller (ovnkube binary) via SetECSInjector.
type ECSInjector interface {
	// Attach installs the TC BPF ECS-injection program on the named interface.
	// ifname is the host-side veth peer name (e.g. "b049782ae4d83_3"),
	// visible from the host network namespace — no netns entry required.
	// TCX ingress on the host-side peer intercepts pod-egress traffic before
	// OVN-K SNAT rewrites ip->saddr, so the pod's real UDN IP is still present.
	Attach(ifname string) error
	// Detach removes the program. No-op if not attached.
	Detach(ifname string) error
}

// ecsInjector is the process-global ECS injection manager.
// nil when --enable-udn-edns is not set or when BPF is not available.
var ecsInjector ECSInjector

// SetECSInjector wires in the concrete ecs.Manager implementation.
// Called from the ovnkube-node main once the feature flag is confirmed
// and the BPF objects have been loaded.
//
// Example (in cmd/ovnkube/ovnkube.go):
//
//	if config.OVNKubernetesFeature.EnableUDNEdns {
//	    m, err := ecs.New()
//	    if err != nil {
//	        klog.Warningf("ECS inject: BPF load failed, DNS isolation disabled: %v", err)
//	    } else {
//	        cni.SetECSInjector(m)
//	        defer m.Close()
//	    }
//	}
func SetECSInjector(inj ECSInjector) {
	ecsInjector = inj
}
