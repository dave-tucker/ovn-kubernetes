// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package object holds the stripped-down cache objects used by the
// ovn-kubernetes CoreDNS plugin.  Only the fields required for DNS record
// synthesis are retained; everything else is discarded at informer-event time
// to keep the in-memory footprint small.
package object

import "net"

// Pod is the minimal pod representation stored in the plugin cache.
type Pod struct {
	// Name is pod.metadata.name.
	Name string
	// Namespace is pod.metadata.namespace.
	Namespace string

	// UDNIPs maps NAD key ("namespace/nad-name") to the list of IPs the pod
	// holds on that network.  Only UDN / CUDN NADs appear here; the default
	// network entry ("default") is skipped.
	UDNIPs map[string][]net.IP

	// DefaultIPs holds the IPs from the pod's infrastructure-locked default
	// network interface.  These are indexed alongside UDNIPs so that DNS
	// queries originating from the default-network interface of a UDN pod
	// (which may happen due to OVN-K service routing or SNAT) are correctly
	// identified and have their UDN membership derived from UDNIPs.
	// Nil for pods that have no default network annotation entry.
	DefaultIPs []net.IP

	// Hostname is pod.spec.hostname (empty string when unset).
	Hostname string
	// Subdomain is pod.spec.subdomain (empty string when unset).
	Subdomain string
}
