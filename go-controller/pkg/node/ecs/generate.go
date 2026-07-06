// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ecs provides a cilium/ebpf-based TC egress BPF program that injects
// EDNS0 Client Subnet (ECS, RFC 7871) options into DNS queries from UDN pods,
// preserving the pod's real UDN IP address before OVN-K SNAT erases it.
//
// The generated Go files allow ovnkube-node to load and attach the program to
// UDN pod veth interfaces as pods are created and deleted.
package ecs

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" EcsInject ./bpf/ecs_inject.bpf.c -- -I/usr/include -I./bpf/headers
