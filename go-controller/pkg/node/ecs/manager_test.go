// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ecs

import (
	"net"
	"testing"
)

// TestManagerNew verifies that the BPF objects load correctly.
// This test requires a Linux host with BTF support (kernel 5.2+).
// It is skipped automatically on unsupported platforms.
func TestManagerNew(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Skipf("cannot load BPF objects (kernel may lack BTF or CAP_BPF): %v", err)
	}
	defer m.Close()

	ifaces := m.AttachedInterfaces()
	if len(ifaces) != 0 {
		t.Errorf("expected no attached interfaces after New(), got %v", ifaces)
	}
}

// TestManagerAttachDetach verifies the attach/detach lifecycle on the loopback
// interface (always present, no CAP_NET_ADMIN issues for root).
func TestManagerAttachDetach(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Skipf("cannot load BPF objects: %v", err)
	}
	defer m.Close()

	lo := "lo"
	if _, err := net.InterfaceByName(lo); err != nil {
		t.Skipf("loopback interface not found: %v", err)
	}

	// First attach.
	if err := m.Attach(lo); err != nil {
		t.Skipf("cannot attach to %q (need CAP_NET_ADMIN / root): %v", lo, err)
	}

	ifaces := m.AttachedInterfaces()
	if len(ifaces) != 1 || ifaces[0] != lo {
		t.Errorf("expected [%q] after Attach, got %v", lo, ifaces)
	}

	// Idempotent second attach.
	if err := m.Attach(lo); err != nil {
		t.Errorf("second Attach should be no-op, got error: %v", err)
	}

	if len(m.AttachedInterfaces()) != 1 {
		t.Error("idempotent Attach should not add a second entry")
	}

	// Detach.
	if err := m.Detach(lo); err != nil {
		t.Errorf("Detach: %v", err)
	}
	if len(m.AttachedInterfaces()) != 0 {
		t.Error("expected no attached interfaces after Detach")
	}

	// Idempotent detach.
	if err := m.Detach(lo); err != nil {
		t.Errorf("second Detach should be no-op, got error: %v", err)
	}
}
