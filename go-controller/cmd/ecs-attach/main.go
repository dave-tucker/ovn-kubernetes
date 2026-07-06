// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// ecs-attach is a developer/testing tool that manually attaches the ECS
// injection BPF program to a network interface.
//
// In production this attachment is done automatically by ovnkube-node when
// --enable-udn-edns is set.  Use ecs-attach to test the BPF program without
// rebuilding the full ovnkube image.
//
// Usage:
//
//	ecs-attach <interface-name>          # attach until Ctrl-C
//	ecs-attach -list                     # show currently attached interfaces
//
// Example (run as root inside the kind worker node):
//
//	# Find the veth peer for a UDN pod's primary interface:
//	ip link | grep $(crictl inspect <container-id> | jq -r '.info.pid')
//
//	ecs-attach c1148175da280_3
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	nodeecs "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/ecs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: ecs-attach <interface-name>\n")
		fmt.Fprintf(os.Stderr, "       ecs-attach -list\n")
		os.Exit(1)
	}

	m, err := nodeecs.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load BPF objects: %v\n", err)
		fmt.Fprintf(os.Stderr, "       kernel 5.8+ with CONFIG_BPF_SYSCALL and CAP_BPF required\n")
		os.Exit(1)
	}
	defer m.Close()

	if os.Args[1] == "-list" {
		ifaces := m.AttachedInterfaces()
		if len(ifaces) == 0 {
			fmt.Println("no interfaces attached")
		}
		for _, i := range ifaces {
			fmt.Println(i)
		}
		return
	}

	ifname := os.Args[1]
	if err := m.Attach(ifname); err != nil {
		fmt.Fprintf(os.Stderr, "error: attach to %q: %v\n", ifname, err)
		os.Exit(1)
	}

	fmt.Printf("✓ ECS injection BPF attached to %q\n", ifname)
	fmt.Printf("  DNS queries from pods using this veth will carry ECS with the pod's\n")
	fmt.Printf("  real UDN IP before OVN-K SNAT replaces the source address.\n")
	fmt.Printf("  Press Ctrl-C to detach and exit.\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Printf("\nDetaching from %q...\n", ifname)
	if err := m.Detach(ifname); err != nil {
		fmt.Fprintf(os.Stderr, "warning: detach: %v\n", err)
	}
}
