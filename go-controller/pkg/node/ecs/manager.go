// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ecs

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"k8s.io/klog/v2"
)

// Manager loads the ECS-injection BPF program once and attaches/detaches it
// to UDN pod veth interfaces as pods are created and deleted.
//
// Intended for use by ovnkube-node: call Attach when a UDN pod veth is
// created, Detach when the pod is deleted.
type Manager struct {
	mu    sync.Mutex
	objs  EcsInjectObjects
	links map[string]link.Link // keyed by interface name
}

// New loads the BPF program from the embedded object bytes.
// Returns an error if the host kernel doesn't support the required features
// (TC egress BPF, bpf_skb_change_tail — available since 5.8).
func New() (*Manager, error) {
	objs := EcsInjectObjects{}
	if err := LoadEcsInjectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading ECS inject BPF objects: %w", err)
	}
	return &Manager{
		objs:  objs,
		links: make(map[string]link.Link),
	}, nil
}

// Attach installs the ECS-injection BPF program as TCX ingress on the
// host-side veth peer (e.g. "b049782ae4d83_3").
//
// Using the host-side peer means no netns entry is required: the interface
// is visible in the host network namespace, which is where ovnkube-node runs.
// TCX ingress on the host-side peer fires for traffic flowing FROM the pod
// (pod-egress), before OVN-K SNAT replaces ip->saddr, so ip->saddr is still
// the pod's real UDN IP when the BPF reads it.
//
// Safe to call multiple times for the same interface (idempotent).
func (m *Manager) Attach(ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.links[ifname]; exists {
		return nil // already attached
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", ifname, err)
	}

	// TCX ingress on the host-side veth peer: fires for traffic FROM the pod
	// before OVS/OVN processes it, so ip->saddr is still the pod's UDN IP.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   m.objs.InjectEcs,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attaching ECS inject to %q: %w", ifname, err)
	}

	m.links[ifname] = l
	klog.V(4).InfoS("ECS inject BPF attached", "iface", ifname)
	return nil
}

// Detach removes the TC egress BPF program from the named interface.
// Safe to call for interfaces that were never attached (no-op).
func (m *Manager) Detach(ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, exists := m.links[ifname]
	if !exists {
		return nil
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("detaching ECS inject from %q: %w", ifname, err)
	}
	delete(m.links, ifname)
	klog.V(4).InfoS("ECS inject BPF detached", "iface", ifname)
	return nil
}

// DetachAll removes the BPF program from every currently-attached interface.
func (m *Manager) DetachAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ifname, l := range m.links {
		if err := l.Close(); err != nil {
			klog.Warningf("ECS inject: failed to detach from %q: %v", ifname, err)
		}
		delete(m.links, ifname)
	}
}

// Close unloads the BPF program and all attached links.
func (m *Manager) Close() error {
	m.DetachAll()
	return m.objs.Close()
}

// AttachedInterfaces returns the names of interfaces that currently have the
// ECS injection program installed — useful for reconciliation loops.
func (m *Manager) AttachedInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.links))
	for k := range m.links {
		out = append(out, k)
	}
	return out
}
