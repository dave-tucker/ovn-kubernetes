// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Command coredns is a reference build of CoreDNS that includes the
// ovn-kubernetes external plugin.
//
// # For dns-operator / OpenShift-DNS
//
// Copy this file into your own CoreDNS build tree, add a blank import for
// the ovn-kubernetes plugin, and ensure your plugin.cfg contains:
//
//	ovn-kubernetes:github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes
//
// placed before the kubernetes entry.  Run `go generate coredns.go` to
// regenerate the directive list, then `go build`.
//
// # For the reference image
//
// Use the Dockerfile at plugin/coredns-ovn-kubernetes/Dockerfile from the
// repository root.  It performs the plugin.cfg + go generate steps for you.
//
// # Corefile placement
//
// The ovn-kubernetes directive must appear before kubernetes in every stanza:
//
//	cluster.local {
//	    ovn-kubernetes
//	    kubernetes cluster.local in-addr.arpa ip6.arpa { pods verified }
//	    cache 30
//	}
package main

import (
	// Standard CoreDNS plugin suite — equivalent to `_ "github.com/coredns/coredns/core/plugin"`
	// but listed explicitly so the set can be audited and trimmed by consumers.
	_ "github.com/coredns/coredns/plugin/any"
	_ "github.com/coredns/coredns/plugin/autopath"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/kubernetes"
	_ "github.com/coredns/coredns/plugin/loadbalance"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/loop"
	_ "github.com/coredns/coredns/plugin/metrics"
	_ "github.com/coredns/coredns/plugin/reload"
	_ "github.com/coredns/coredns/plugin/rewrite"
	_ "github.com/coredns/coredns/plugin/whoami"

	// OVN-Kubernetes plugin — registered via init(); must appear before the
	// kubernetes blank import so it is inserted ahead of kubernetes in the
	// Directives slice.
	_ "github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes"

	"github.com/coredns/coredns/coremain"
)

func main() {
	coremain.Run()
}
