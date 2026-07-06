// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ovnkubernetes is a CoreDNS plugin that serves DNS records for pods
// on OVN-Kubernetes User Defined Networks (UDN) and Cluster User Defined
// Networks (CUDN).
//
// Registration:
//
//	import _ "github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes"
//
// Corefile example:
//
//	cluster.local {
//	    ovn-kubernetes
//	    kubernetes cluster.local in-addr.arpa ip6.arpa { pods verified }
//	    cache 30
//	}
//
//	in-addr.arpa  { ovn-kubernetes; kubernetes cluster.local in-addr.arpa ip6.arpa }
//	ip6.arpa      { ovn-kubernetes; kubernetes cluster.local in-addr.arpa ip6.arpa }
//
// The ovn-kubernetes directive must appear before the kubernetes directive in
// each stanza.  No arguments are required; all data is auto-discovered from
// the Kubernetes API.
package ovnkubernetes

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	cncversioned "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/clusternetworkconnect/v1/apis/clientset/versioned"
	cncinformers "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/clusternetworkconnect/v1/apis/informers/externalversions"
	cnclisters "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/clusternetworkconnect/v1/apis/listers/clusternetworkconnect/v1"
	udnversioned "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/clientset/versioned"
	udninformers "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/informers/externalversions"
	udnlisters "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/listers/userdefinednetwork/v1"

	corev1informers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	// When consumed via plugin.cfg + go generate (e.g. this Dockerfile build,
	// or the dns-operator), the generated zdirectives.go already places
	// pluginName before "kubernetes" in the Directives slice.  Only insert it
	// when it is absent — that is the "blank import only" case used by
	// dns-operator or the reference cmd/coredns build that skips go generate.
	alreadyPresent := false
	for _, d := range dnsserver.Directives {
		if d == pluginName {
			alreadyPresent = true
			break
		}
	}
	if !alreadyPresent {
		for i, d := range dnsserver.Directives {
			if d == "kubernetes" {
				dnsserver.Directives = append(dnsserver.Directives[:i],
					append([]string{pluginName}, dnsserver.Directives[i:]...)...)
				break
			}
		}
	}
	plugin.Register(pluginName, setup)
}

func setup(c *caddy.Controller) error {
	p, err := parseConfig(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	c.OnStartup(func() error { return p.OnStartup() })
	c.OnShutdown(func() error { return p.OnShutdown() })

	return nil
}

// parseConfig reads the Corefile directive for the ovn-kubernetes plugin.
// Currently the plugin takes no arguments; future versions may accept a
// kubeconfig path or resync interval.
func parseConfig(c *caddy.Controller) (*Plugin, error) {
	// Network isolation is on by default; use disable-network-isolation to opt out.
	p := &Plugin{
		cache:            newCache(),
		EnforceIsolation: true,
	}

	for c.Next() {
		// CoreDNS stores server-block keys as URIs: "dns://cluster.local.:53".
		// Normalise them to plain FQDN labels so plugin.Zones.Matches works.
		p.Zones = plugin.OriginsFromArgsOrServerBlock(nil, c.ServerBlockKeys)
		// No arguments expected.
		if c.NextArg() {
			return nil, c.ArgErr()
		}
		for c.NextBlock() {
			switch c.Val() {
			case "fallthrough":
				p.Fall.SetZonesFromArgs(c.RemainingArgs())
			case "disable-network-isolation":
				p.EnforceIsolation = false
			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if len(p.Zones) == 0 {
		p.Zones = []string{"."}
	}

	return p, nil
}

// stopCh is used to signal informers to stop.
var stopCh chan struct{}

// cacheReady is set to 1 once informer caches have synced.
var cacheReady atomic.Int32

// OnStartup starts the informers. Cache sync happens asynchronously so that
// CoreDNS can open its listeners immediately; the plugin's Ready() method
// returns false until the sync completes and queries are served only after
// the CoreDNS readiness gate has passed.
func (p *Plugin) OnStartup() error {
	cacheReady.Store(0)
	stopCh = make(chan struct{})

	cfg, err := buildKubeConfig()
	if err != nil {
		return fmt.Errorf("ovn-kubernetes CoreDNS: failed to build kube config: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("ovn-kubernetes CoreDNS: failed to create k8s client: %w", err)
	}

	udnClient, err := udnversioned.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("ovn-kubernetes CoreDNS: failed to create UDN client: %w", err)
	}

	cncClient, err := cncversioned.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("ovn-kubernetes CoreDNS: failed to create CNC client: %w", err)
	}

	resync := 30 * time.Second

	k8sFactory := corev1informers.NewSharedInformerFactory(k8sClient, resync)
	udnFactory := udninformers.NewSharedInformerFactory(udnClient, resync)
	cncFactory := cncinformers.NewSharedInformerFactory(cncClient, resync)

	podInformer := k8sFactory.Core().V1().Pods().Informer()
	udnInformer := udnFactory.K8s().V1().UserDefinedNetworks().Informer()
	cudnInformer := udnFactory.K8s().V1().ClusterUserDefinedNetworks().Informer()
	cncInformer := cncFactory.K8s().V1().ClusterNetworkConnects().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    p.cache.OnPodAdd,
		UpdateFunc: p.cache.OnPodUpdate,
		DeleteFunc: p.cache.OnPodDelete,
	})
	udnInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    p.cache.OnUDNAdd,
		UpdateFunc: p.cache.OnUDNUpdate,
		DeleteFunc: p.cache.OnUDNDelete,
	})
	cudnInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    p.cache.OnCUDNAdd,
		UpdateFunc: p.cache.OnCUDNUpdate,
		DeleteFunc: p.cache.OnCUDNDelete,
	})
	cncInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    p.cache.OnCNCAdd,
		UpdateFunc: p.cache.OnCNCUpdate,
		DeleteFunc: p.cache.OnCNCDelete,
	})

	k8sFactory.Start(stopCh)
	udnFactory.Start(stopCh)
	cncFactory.Start(stopCh)

	// Sync caches in the background so CoreDNS can open its listeners
	// immediately. Queries are held off by Ready() returning false until
	// the sync completes.
	go func() {
		if !cache.WaitForCacheSync(stopCh,
			podInformer.HasSynced,
			udnInformer.HasSynced,
			cudnInformer.HasSynced,
			cncInformer.HasSynced,
		) {
			// stopCh closed during shutdown — not an error.
			return
		}
		// Wire up listers now that caches are populated.
		p.cache.SetListers(
			udnlisters.NewUserDefinedNetworkLister(udnInformer.GetIndexer()),
			udnlisters.NewClusterUserDefinedNetworkLister(cudnInformer.GetIndexer()),
			cnclisters.NewClusterNetworkConnectLister(cncInformer.GetIndexer()),
		)
		cacheReady.Store(1)
	}()

	return nil
}

// OnShutdown stops the informers.
func (p *Plugin) OnShutdown() error {
	if stopCh != nil {
		close(stopCh)
		stopCh = nil
	}
	return nil
}

// buildKubeConfig returns an in-cluster config if running inside a pod, or
// falls back to the KUBECONFIG environment variable / default kubeconfig.
func buildKubeConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}
