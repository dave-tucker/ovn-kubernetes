// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovnkubernetes

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"

	"github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes/object"
	"k8s.io/klog/v2"
)

const pluginName = "ovn-kubernetes"

// Plugin is the CoreDNS plugin struct.  It satisfies plugin.Handler and the
// autopath.AutoPather interface.
type Plugin struct {
	Next plugin.Handler
	Fall fall.F

	// Zones lists the DNS zones this plugin answers for.
	Zones []string

	// cache is the in-memory state built from informer events.
	cache *Cache

	// EnforceIsolation, when true, restricts DNS resolution to the querying
	// pod's own network and its direct ClusterNetworkConnect peers.
	// Default-network pods (source IP not in any UDN/CUDN) are always exempt.
	// Both forward (A/AAAA) and reverse (PTR) queries are gated.
	// Blocked queries receive NXDOMAIN.
	EnforceIsolation bool
}

// Name implements plugin.Handler.
func (p *Plugin) Name() string { return pluginName }

// Ready reports whether the informer caches have synced.  Used by the CoreDNS
// health plugin.
func (p *Plugin) Ready() bool {
	// Return true only after the background cache sync has completed.
	return p.cache != nil && cacheReady.Load() == 1
}

// ServeDNS implements plugin.Handler.
func (p *Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// Match the query against our zones.
	zone := plugin.Zones(p.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	qname := state.Name()
	qtype := state.QType()

	// PTR queries are handled separately.
	if qtype == dns.TypePTR {
		return p.servePTR(ctx, state, qname, w, r)
	}

	// Only answer A and AAAA.
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	// Strip trailing dot for parsing.
	bare := strings.TrimSuffix(qname, ".")
	pq := parseQuery(bare, strings.TrimSuffix(zone, "."))

	switch pq.Kind {
	case queryUDNPodIP:
		return p.serveUDNPodIP(ctx, state, pq, qtype, w, r)
	case queryCUDNPodIP:
		return p.serveCUDNPodIP(ctx, state, pq, qtype, w, r)
	case queryUDNHostname:
		return p.serveHostname(ctx, state, pq, qtype, true, w, r)
	case queryCUDNHostname:
		return p.serveHostname(ctx, state, pq, qtype, false, w, r)
	default:
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}
}

// serveUDNPodIP answers A/AAAA for a UDN pod-IP query.
func (p *Plugin) serveUDNPodIP(
	ctx context.Context,
	state request.Request,
	pq parsedQuery,
	qtype uint16,
	w dns.ResponseWriter,
	r *dns.Msg,
) (int, error) {
	udnKey := udnNADKey(pq.Namespace, pq.NetworkName)
	if !p.cache.IsUDN(udnKey) {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}
	if p.EnforceIsolation && !p.cache.CanQuery(extractSourceIP(state), udnKey) {
		return nxDomain(state, w, r)
	}

	pod := p.cache.PodByUDNIP(pq.IP.String())
	if pod == nil {
		return nxDomain(state, w, r)
	}

	// Verify the pod is actually on this UDN.
	ips, ok := pod.UDNIPs[udnKey]
	if !ok {
		return nxDomain(state, w, r)
	}

	rrs := ipsToRRs(state.Name(), ips, qtype)
	if len(rrs) == 0 {
		return nxDomain(state, w, r)
	}
	return success(state, w, r, rrs)
}

// serveCUDNPodIP answers A/AAAA for a CUDN pod-IP query.
func (p *Plugin) serveCUDNPodIP(
	ctx context.Context,
	state request.Request,
	pq parsedQuery,
	qtype uint16,
	w dns.ResponseWriter,
	r *dns.Msg,
) (int, error) {
	if !p.cache.IsCUDN(pq.NetworkName) {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}
	if p.EnforceIsolation &&
		!p.cache.CanQuery(extractSourceIP(state), networkKeyPrefixCUDN+pq.NetworkName) {
		return nxDomain(state, w, r)
	}

	pod := p.cache.PodByUDNIP(pq.IP.String())
	if pod == nil {
		return nxDomain(state, w, r)
	}

	// Find the pod's NAD key for this CUDN: "pod-namespace/cudn-name".
	nadKey := pod.Namespace + "/" + pq.NetworkName
	ips, ok := pod.UDNIPs[nadKey]
	if !ok {
		return nxDomain(state, w, r)
	}

	rrs := ipsToRRs(state.Name(), ips, qtype)
	if len(rrs) == 0 {
		return nxDomain(state, w, r)
	}
	return success(state, w, r, rrs)
}

// serveHostname answers A/AAAA for a hostname+subdomain query.
// isUDN distinguishes UDN (namespace-scoped) from CUDN (cluster-scoped).
func (p *Plugin) serveHostname(
	ctx context.Context,
	state request.Request,
	pq parsedQuery,
	qtype uint16,
	isUDN bool,
	w dns.ResponseWriter,
	r *dns.Msg,
) (int, error) {
	// For the NAD key we need the pod's namespace.  Hostname+subdomain records
	// in Kubernetes DNS are per-pod, so we iterate all pods with this hostname
	// and return all matching IPs.
	//
	// For UDN:  NAD key = pq.Namespace + "/" + pq.NetworkName
	// For CUDN: NAD key = pod.Namespace + "/" + pq.NetworkName (per pod)

	var pods []*object.Pod

	if isUDN {
		udnKey := udnNADKey(pq.Namespace, pq.NetworkName)
		if !p.cache.IsUDN(udnKey) {
			return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
		}
		if p.EnforceIsolation && !p.cache.CanQuery(extractSourceIP(state), udnKey) {
			return nxDomain(state, w, r)
		}
		pods = p.cache.PodsWithHostname(pq.Hostname, pq.Subdomain, udnKey)
	} else {
		if !p.cache.IsCUDN(pq.NetworkName) {
			return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
		}
		if p.EnforceIsolation &&
			!p.cache.CanQuery(extractSourceIP(state), networkKeyPrefixCUDN+pq.NetworkName) {
			return nxDomain(state, w, r)
		}
		// For CUDN, the NAD key varies by pod namespace; collect all pods with
		// any NAD key ending in "/cudn-name".
		allPods := p.cache.PodsWithAnyHostname(pq.Hostname, pq.Subdomain)
		for _, pod := range allPods {
			nadKey := pod.Namespace + "/" + pq.NetworkName
			if _, ok := pod.UDNIPs[nadKey]; ok {
				pods = append(pods, pod)
			}
		}
	}

	if len(pods) == 0 {
		return nxDomain(state, w, r)
	}

	var rrs []dns.RR
	for _, pod := range pods {
		var nadKey string
		if isUDN {
			nadKey = udnNADKey(pq.Namespace, pq.NetworkName)
		} else {
			nadKey = pod.Namespace + "/" + pq.NetworkName
		}
		rrs = append(rrs, ipsToRRs(state.Name(), pod.UDNIPs[nadKey], qtype)...)
	}

	if len(rrs) == 0 {
		return nxDomain(state, w, r)
	}
	return success(state, w, r, rrs)
}

// servePTR answers a PTR query for an IP in a UDN/CUDN subnet.
func (p *Plugin) servePTR(
	ctx context.Context,
	state request.Request,
	qname string,
	w dns.ResponseWriter,
	r *dns.Msg,
) (int, error) {
	ip := extractIPFromPTR(qname)
	if ip == nil {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	networkKey, isCUDN, found := p.cache.NetworkKeyForIP(ip)
	if !found {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}
	if p.EnforceIsolation && !p.cache.CanQuery(extractSourceIP(state), networkKey) {
		return nxDomain(state, w, r)
	}

	pod := p.cache.PodByUDNIP(ip.String())
	if pod == nil {
		return nxDomain(state, w, r)
	}

	// Build the forward target name.
	zone := ""
	for _, z := range p.Zones {
		if !strings.HasSuffix(z, "arpa.") && !strings.HasSuffix(z, "arpa") {
			zone = strings.Trim(z, ".")
			break
		}
	}
	if zone == "" {
		zone = "cluster.local"
	}

	target := ptrTarget(ip, networkKey, zone, isCUDN)
	if target == "" {
		return nxDomain(state, w, r)
	}

	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(qname),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    30,
		},
		Ptr: target,
	}

	return success(state, w, r, []dns.RR{ptr})
}

// AutoPath implements the autopath.AutoPather interface.
// It returns a UDN-aware search path for the pod identified by the query's
// source IP.  Returning nil delegates to the kubernetes plugin's AutoPath.
func (p *Plugin) AutoPath(state request.Request) []string {
	srcIP := extractSourceIP(state)
	pod := p.cache.PodByUDNIP(srcIP)
	if pod == nil {
		return nil
	}
	return p.searchPathForPod(pod)
}

// searchPathForPod builds the autopath search list for a pod:
//  1. Primary UDN/CUDN first
//  2. Secondary UDNs/CUDNs
//  3. Direct CNC peers (one hop only)
//  4. Standard Kubernetes fallbacks
//  5. "" sentinel
func (p *Plugin) searchPathForPod(pod *object.Pod) []string {
	zone := ""
	for _, z := range p.Zones {
		if !strings.Contains(z, "arpa") {
			zone = strings.Trim(z, ".")
			break
		}
	}
	if zone == "" {
		zone = "cluster.local"
	}

	// Collect this pod's network keys.
	netKeys := p.cache.InternalKeysForPod(pod)

	// Build search path, deduplicating as we go.
	seen := make(map[string]bool)
	var path []string

	addEntry := func(key string) {
		entry := nadKeyToSearchEntry(key, zone)
		if entry != "" && !seen[entry] {
			seen[entry] = true
			path = append(path, entry)
		}
	}

	// Pod's own networks.
	for _, k := range netKeys {
		addEntry(k)
	}

	// Direct CNC peers (one hop only).
	for _, k := range netKeys {
		for _, peer := range p.cache.SearchPathPeers(k) {
			addEntry(peer)
		}
	}

	// Standard Kubernetes search path fallbacks.
	for _, suffix := range []string{
		pod.Namespace + ".svc." + zone,
		"svc." + zone,
		zone,
	} {
		if !seen[suffix] {
			seen[suffix] = true
			path = append(path, suffix)
		}
	}

	// Sentinel required by CoreDNS autopath contract.
	path = append(path, "")
	return path
}

// ---- DNS helpers ----

// extractSourceIP returns the best available source IP for isolation decisions.
//
// When the ovnkube-node ECS-injection BPF program is active, DNS queries from
// UDN pods carry an EDNS0 Client Subnet option whose address is the pod's real
// UDN IP (captured before OVN-K SNAT replaces it with the join-subnet IP).
// We prefer that over the network-layer source address.
func extractSourceIP(state request.Request) string {
	// 1. Try EDNS0 Client Subnet (injected by our TC BPF program on the UDN veth).
	// The BPF program captures ip->saddr before OVN-K SNAT replaces it with the
	// join-subnet IP, so the ECS address is the pod's real UDN IP.
	if opt := state.Req.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
				if subnet.Address != nil {
					src := subnet.Address.String()
					klog.InfoS("ovn-kubernetes: ECS source from BPF injection",
						"ecs-ip", src,
						"net-src", state.IP(),
						"query", state.Name())
					return src
				}
			}
		}
	}
	// 2. Fall back to the network-layer source IP.
	ip := state.IP()
	if ip == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}

// stripECS removes the EDNS0 Client Subnet option from a DNS message.
// Called on the response path so the pod never sees the injected option.
func stripECS(m *dns.Msg) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	filtered := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isECS := o.(*dns.EDNS0_SUBNET); !isECS {
			filtered = append(filtered, o)
		}
	}
	opt.Option = filtered
	// If the OPT RR is now empty and was not in the original request, drop it.
	if len(opt.Option) == 0 {
		m.Extra = m.Extra[:0]
	}
}

// ipsToRRs converts a list of IPs to A or AAAA resource records.
func ipsToRRs(name string, ips []net.IP, qtype uint16) []dns.RR {
	var rrs []dns.RR
	for _, ip := range ips {
		switch {
		case qtype == dns.TypeA && ip.To4() != nil:
			rrs = append(rrs, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: ip.To4(),
			})
		case qtype == dns.TypeAAAA && ip.To4() == nil:
			rrs = append(rrs, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				AAAA: ip.To16(),
			})
		}
	}
	return rrs
}

// success sends a NOERROR response with the given answer section.
// It strips any EDNS0 Client Subnet option injected by our BPF program before
// returning the response to the client — the pod must not see the ECS option.
func success(state request.Request, w dns.ResponseWriter, r *dns.Msg, rrs []dns.RR) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = rrs
	stripECS(m)
	w.WriteMsg(m) //nolint:errcheck
	return dns.RcodeSuccess, nil
}



// nxDomain sends an NXDOMAIN response, stripping any injected ECS option.
func nxDomain(state request.Request, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.SetRcode(r, dns.RcodeNameError)
	m.Authoritative = true
	stripECS(m)
	w.WriteMsg(m) //nolint:errcheck
	return dns.RcodeNameError, nil
}

// PodsWithAnyHostname returns all pods with the given hostname and subdomain,
// regardless of which network they are on.  Used for CUDN hostname queries.
func (c *Cache) PodsWithAnyHostname(hostname, subdomain string) []*object.Pod {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*object.Pod
	for _, p := range c.pods {
		if p.Hostname == hostname && p.Subdomain == subdomain {
			out = append(out, p)
		}
	}
	return out
}
