// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovnkubernetes

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	udnv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	ovntypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes/object"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---- test infrastructure ----

// recorder is a dns.ResponseWriter that captures the last written message.
type recorder struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

func newRecorder(rw dns.ResponseWriter) *recorder { return &recorder{ResponseWriter: rw} }

func (r *recorder) WriteMsg(m *dns.Msg) error {
	r.Msg = m
	return nil
}

// newPlugin creates a Plugin with isolation DISABLED for record-serving tests.
// Most unit tests exercise the DNS record logic independently of isolation;
// isolation-specific tests use newIsolatedPlugin.
func newPlugin(zones []string) *Plugin {
	return &Plugin{
		Zones:            zones,
		cache:            newCache(),
		Next:             test.ErrorHandler(),
		EnforceIsolation: false,
	}
}

// addPodToCache directly inserts a pod and its UDN IPs into the cache.
func addPodToCache(c *Cache, namespace, name, nadKey string, ips []string) {
	ipList := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		ipList = append(ipList, net.ParseIP(s))
	}
	pod := &object.Pod{
		Name:      name,
		Namespace: namespace,
		UDNIPs:    map[string][]net.IP{nadKey: ipList},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range ipList {
		c.udnIPIndex[ip.String()] = pod
	}
	c.pods[namespace+"/"+name] = pod
}

// addPodWithHostnameToCache inserts a pod with hostname/subdomain fields set.
func addPodWithHostnameToCache(c *Cache, namespace, name, nadKey, hostname, subdomain string, ips []string) {
	ipList := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		ipList = append(ipList, net.ParseIP(s))
	}
	pod := &object.Pod{
		Name:      name,
		Namespace: namespace,
		Hostname:  hostname,
		Subdomain: subdomain,
		UDNIPs:    map[string][]net.IP{nadKey: ipList},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range ipList {
		c.udnIPIndex[ip.String()] = pod
	}
	c.pods[namespace+"/"+name] = pod
}

// sendQuery is a convenience wrapper around ServeDNS.
func sendQuery(t *testing.T, p *Plugin, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	rec := newRecorder(&test.ResponseWriter{})
	_, err := p.ServeDNS(context.Background(), rec, req)
	if err != nil && rec.Msg == nil {
		t.Fatalf("ServeDNS returned error with no message: %v", err)
	}
	return rec.Msg
}

// newTestUDN creates a minimal UserDefinedNetwork for event-handler tests.
func newTestUDN(namespace, name string) *udnv1.UserDefinedNetwork {
	return &udnv1.UserDefinedNetwork{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: udnv1.UserDefinedNetworkSpec{
			Topology: "Layer2",
			Layer2: &udnv1.Layer2Config{
				Role:    "Primary",
				Subnets: udnv1.DualStackCIDRs{"10.128.0.0/16"},
			},
		},
	}
}

// ---- A/AAAA record tests ----

func TestUDNPodIP_A(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	addPodToCache(p.cache, "default", "web-0", "default/my-net", []string{"10.128.1.5"})

	msg := sendQuery(t, p, "10-128-1-5.my-net.default.pod.cluster.local", dns.TypeA)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", msg.Answer[0])
	}
	if a.A.String() != "10.128.1.5" {
		t.Errorf("expected 10.128.1.5, got %s", a.A)
	}
}

func TestUDNPodIP_AAAA(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.udnNames["foo/blue-net"] = struct{}{}
	addPodToCache(p.cache, "foo", "srv-1", "foo/blue-net", []string{"fd00::1"})

	msg := sendQuery(t, p, "fd00--1.blue-net.foo.pod.cluster.local", dns.TypeAAAA)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	_, ok := msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", msg.Answer[0])
	}
}

func TestUDNPodIP_UnknownUDN_FallsThrough(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	// "ghost-net" is not registered — should fall through to Next (ErrorHandler).
	msg := sendQuery(t, p, "10-128-1-5.ghost-net.default.pod.cluster.local", dns.TypeA)
	// ErrorHandler returns SERVFAIL.
	if msg != nil && msg.Rcode == dns.RcodeNameError {
		t.Error("should not return NXDOMAIN; expected SERVFAIL from ErrorHandler")
	}
}

func TestUDNPodIP_NXDOMAIN_IPNotFound(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	// No pod with IP 10.128.1.99.

	msg := sendQuery(t, p, "10-128-1-99.my-net.default.pod.cluster.local", dns.TypeA)
	if msg == nil || msg.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %v", msg)
	}
}

func TestCUDNPodIP_A(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.cudnNames["global-net"] = struct{}{}
	addPodToCache(p.cache, "bar", "api-0", "bar/global-net", []string{"10.201.2.7"})

	msg := sendQuery(t, p, "10-201-2-7.global-net.pod.cluster.local", dns.TypeA)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record")
	}
	if a.A.String() != "10.201.2.7" {
		t.Errorf("wrong IP: %s", a.A)
	}
}

// ---- PTR record tests ----

func TestPTR_UDN(t *testing.T) {
	p := newPlugin([]string{"cluster.local.", "in-addr.arpa."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	_, subnet, _ := net.ParseCIDR("10.128.0.0/16")
	p.cache.udnSubnets["default/my-net"] = []*net.IPNet{subnet}
	addPodToCache(p.cache, "default", "web-0", "default/my-net", []string{"10.128.1.5"})

	msg := sendQuery(t, p, "5.1.128.10.in-addr.arpa", dns.TypePTR)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 PTR answer, got %d", len(msg.Answer))
	}
	ptr, ok := msg.Answer[0].(*dns.PTR)
	if !ok {
		t.Fatalf("expected PTR record")
	}
	want := "10-128-1-5.my-net.default.pod.cluster.local."
	if ptr.Ptr != want {
		t.Errorf("PTR target: got %q, want %q", ptr.Ptr, want)
	}
}

func TestPTR_CUDN(t *testing.T) {
	p := newPlugin([]string{"cluster.local.", "in-addr.arpa."})
	p.cache.cudnNames["blue-net"] = struct{}{}
	_, subnet, _ := net.ParseCIDR("10.201.0.0/16")
	p.cache.cudnSubnets["blue-net"] = []*net.IPNet{subnet}
	addPodToCache(p.cache, "baz", "svc-0", "baz/blue-net", []string{"10.201.2.7"})

	msg := sendQuery(t, p, "7.2.201.10.in-addr.arpa", dns.TypePTR)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	ptr, ok := msg.Answer[0].(*dns.PTR)
	if !ok {
		t.Fatalf("expected PTR record")
	}
	want := "10-201-2-7.blue-net.pod.cluster.local."
	if ptr.Ptr != want {
		t.Errorf("PTR target: got %q, want %q", ptr.Ptr, want)
	}
}

func TestPTR_NoSubnetMatch_FallsThrough(t *testing.T) {
	p := newPlugin([]string{"cluster.local.", "in-addr.arpa."})
	// No UDN/CUDN subnets — falls through to ErrorHandler.
	_ = sendQuery(t, p, "1.2.3.4.in-addr.arpa", dns.TypePTR)
	// No assertion on rcode — just verify no panic.
}

// ---- Hostname + subdomain tests ----

func TestUDNHostname(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	addPodWithHostnameToCache(p.cache, "default", "myhost", "default/my-net", "myhost", "mysvc", []string{"10.128.1.10"})

	msg := sendQuery(t, p, "myhost.mysvc.my-net.default.svc.cluster.local", dns.TypeA)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
}

func TestCUDNHostname(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.cudnNames["blue-net"] = struct{}{}
	addPodWithHostnameToCache(p.cache, "baz", "myhost", "baz/blue-net", "myhost", "mysvc", []string{"10.201.2.7"})

	msg := sendQuery(t, p, "myhost.mysvc.blue-net.svc.cluster.local", dns.TypeA)
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %v", msg)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
}

// ---- Autopath tests ----
// Autopath is tested by calling searchPathForPod directly to avoid needing
// a live DNS query with a specific source IP.

func TestAutoPath_UDNPod(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.udnNames["foo/my-net"] = struct{}{}
	addPodToCache(p.cache, "foo", "web-0", "foo/my-net", []string{"10.128.1.5"})

	pod := p.cache.PodByUDNIP("10.128.1.5")
	if pod == nil {
		t.Fatal("pod not found in cache")
	}
	path := p.searchPathForPod(pod)

	if len(path) == 0 {
		t.Fatal("expected non-empty autopath result")
	}
	if path[0] != "my-net.foo.svc.cluster.local" {
		t.Errorf("path[0]: got %q, want %q", path[0], "my-net.foo.svc.cluster.local")
	}
	if path[len(path)-1] != "" {
		t.Errorf("last entry: got %q, want empty string sentinel", path[len(path)-1])
	}
}

func TestAutoPath_CUDNPod(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.cudnNames["blue-net"] = struct{}{}
	addPodToCache(p.cache, "bar", "api-0", "bar/blue-net", []string{"10.201.2.7"})

	pod := p.cache.PodByUDNIP("10.201.2.7")
	if pod == nil {
		t.Fatal("pod not found")
	}
	path := p.searchPathForPod(pod)

	if path[0] != "blue-net.svc.cluster.local" {
		t.Errorf("path[0]: got %q, want %q", path[0], "blue-net.svc.cluster.local")
	}
	if path[len(path)-1] != "" {
		t.Errorf("last entry: want empty sentinel, got %q", path[len(path)-1])
	}
}

func TestAutoPath_CNCPeer(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})
	p.cache.udnNames["frontend/fe-net"] = struct{}{}
	p.cache.cudnNames["backend-net"] = struct{}{}
	p.cache.cncPeers["frontend/fe-net"] = []string{"cudn:backend-net"}

	addPodToCache(p.cache, "frontend", "web", "frontend/fe-net", []string{"10.128.1.5"})

	pod := p.cache.PodByUDNIP("10.128.1.5")
	if pod == nil {
		t.Fatal("pod not found")
	}
	path := p.searchPathForPod(pod)

	containsFE, containsBE := false, false
	for _, e := range path {
		if e == "fe-net.frontend.svc.cluster.local" {
			containsFE = true
		}
		if e == "backend-net.svc.cluster.local" {
			containsBE = true
		}
	}
	if !containsFE {
		t.Errorf("missing fe-net entry in path: %v", path)
	}
	if !containsBE {
		t.Errorf("missing backend-net peer entry in path: %v", path)
	}
}

func TestAutoPath_NonUDNPod_ReturnsNil(t *testing.T) {
	p := newPlugin([]string{"cluster.local."})

	req := new(dns.Msg)
	req.SetQuestion("svc.cluster.local.", dns.TypeA)
	state := request.Request{W: &test.ResponseWriter{}, Req: req}

	path := p.AutoPath(state)
	if path != nil {
		t.Errorf("expected nil for non-UDN source IP, got %v", path)
	}
}

// ---- Pod annotation event handler tests ----

func TestOnPodAdd_ParsesAnnotation(t *testing.T) {
	c := newCache()
	c.udnNames["default/my-net"] = struct{}{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-0",
			Namespace: "default",
			Annotations: map[string]string{
				ovntypes.OvnPodAnnotationName: `{
					"default": {"ip_addresses":["192.168.0.1/24"],"mac_address":"0a:58:c0:a8:00:01"},
					"default/my-net": {"ip_addresses":["10.128.1.5/24"],"mac_address":"0a:58:0a:80:01:05"}
				}`,
			},
		},
	}

	c.OnPodAdd(pod)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if p, ok := c.udnIPIndex["10.128.1.5"]; !ok {
		t.Fatal("expected 10.128.1.5 to be indexed")
	} else if p.Name != "web-0" {
		t.Errorf("pod name: got %q, want web-0", p.Name)
	}

	// The default-network IP of a UDN pod IS indexed (so DNS queries from
	// the infrastructure-locked interface can still be attributed to the pod).
	if p2, ok := c.udnIPIndex["192.168.0.1"]; !ok {
		t.Error("default-network IP of a UDN pod should be indexed for source-IP lookup")
	} else if p2.Name != "web-0" {
		t.Errorf("default-net IP indexed to wrong pod: got %q", p2.Name)
	}
}

func TestOnPodDelete_RemovesIndex(t *testing.T) {
	c := newCache()
	c.udnNames["default/my-net"] = struct{}{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-0",
			Namespace: "default",
			Annotations: map[string]string{
				ovntypes.OvnPodAnnotationName: `{"default/my-net":{"ip_addresses":["10.128.1.5/24"],"mac_address":"0a:00:00:00:00:01"}}`,
			},
		},
	}
	c.OnPodAdd(pod)
	c.OnPodDelete(pod)

	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.udnIPIndex["10.128.1.5"]; ok {
		t.Error("IP should have been removed after pod delete")
	}
}

// ---- parse.go unit tests ----

func TestParseQuery_UDNPodIP(t *testing.T) {
	pq := parseQuery("10-128-1-5.my-net.default.pod.cluster.local", "cluster.local")
	if pq.Kind != queryUDNPodIP {
		t.Fatalf("expected queryUDNPodIP, got %v", pq.Kind)
	}
	if pq.IP.String() != "10.128.1.5" {
		t.Errorf("IP: got %s", pq.IP)
	}
	if pq.NetworkName != "my-net" || pq.Namespace != "default" {
		t.Errorf("network/ns: got %q/%q", pq.NetworkName, pq.Namespace)
	}
}

func TestParseQuery_CUDNPodIP(t *testing.T) {
	pq := parseQuery("10-201-2-7.blue-net.pod.cluster.local", "cluster.local")
	if pq.Kind != queryCUDNPodIP {
		t.Fatalf("expected queryCUDNPodIP, got %v", pq.Kind)
	}
	if pq.IP.String() != "10.201.2.7" {
		t.Errorf("IP: got %s", pq.IP)
	}
	if pq.NetworkName != "blue-net" {
		t.Errorf("NetworkName: got %q", pq.NetworkName)
	}
}

func TestParseQuery_UDNHostname(t *testing.T) {
	pq := parseQuery("myhost.mysvc.my-net.default.svc.cluster.local", "cluster.local")
	if pq.Kind != queryUDNHostname {
		t.Fatalf("expected queryUDNHostname, got %v", pq.Kind)
	}
	if pq.Hostname != "myhost" || pq.Subdomain != "mysvc" {
		t.Errorf("hostname/subdomain: got %q/%q", pq.Hostname, pq.Subdomain)
	}
	if pq.NetworkName != "my-net" || pq.Namespace != "default" {
		t.Errorf("network/ns: got %q/%q", pq.NetworkName, pq.Namespace)
	}
}

func TestParseQuery_CUDNHostname(t *testing.T) {
	pq := parseQuery("myhost.mysvc.blue-net.svc.cluster.local", "cluster.local")
	if pq.Kind != queryCUDNHostname {
		t.Fatalf("expected queryCUDNHostname, got %v", pq.Kind)
	}
	if pq.NetworkName != "blue-net" {
		t.Errorf("NetworkName: got %q", pq.NetworkName)
	}
}

func TestParseQuery_Unknown(t *testing.T) {
	cases := []string{
		"my-service.default.svc.cluster.local",
		"pod.cluster.local",
		"cluster.local",
		"",
	}
	for _, qname := range cases {
		pq := parseQuery(qname, "cluster.local")
		if pq.Kind != queryUnknown {
			t.Errorf("%q: expected queryUnknown, got %v", qname, pq.Kind)
		}
	}
}

func TestDashedToIP(t *testing.T) {
	cases := []struct {
		dashed string
		want   string
	}{
		{"10-128-1-5", "10.128.1.5"},
		{"10-0-0-1", "10.0.0.1"},
		{"fd00--1", "fd00::1"},
	}
	for _, tc := range cases {
		ip := dashedToIP(tc.dashed)
		if ip == nil || ip.String() != tc.want {
			t.Errorf("dashedToIP(%q): got %v, want %s", tc.dashed, ip, tc.want)
		}
	}
}

func TestIPToDashed(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"10.128.1.5", "10-128-1-5"},
		{"fd00::1", "fd00--1"},
	}
	for _, tc := range cases {
		s := ipToDashed(net.ParseIP(tc.raw))
		if s != tc.want {
			t.Errorf("ipToDashed(%q): got %q, want %q", tc.raw, s, tc.want)
		}
	}
}

// ---- reverse.go unit tests ----

func TestExtractIPFromPTR_IPv4(t *testing.T) {
	ip := extractIPFromPTR("5.1.128.10.in-addr.arpa.")
	if ip == nil || ip.String() != "10.128.1.5" {
		t.Errorf("got %v", ip)
	}
}

func TestExtractIPFromPTR_Invalid(t *testing.T) {
	ip := extractIPFromPTR("not-a-ptr-name")
	if ip != nil {
		t.Errorf("expected nil, got %v", ip)
	}
}

func TestPtrTarget_UDN(t *testing.T) {
	ip := net.ParseIP("10.128.1.5")
	target := ptrTarget(ip, "default/my-net", "cluster.local", false)
	want := "10-128-1-5.my-net.default.pod.cluster.local."
	if target != want {
		t.Errorf("got %q, want %q", target, want)
	}
}

func TestPtrTarget_CUDN(t *testing.T) {
	ip := net.ParseIP("10.201.2.7")
	target := ptrTarget(ip, "cudn:blue-net", "cluster.local", true)
	want := "10-201-2-7.blue-net.pod.cluster.local."
	if target != want {
		t.Errorf("got %q, want %q", target, want)
	}
}

// ---- CNC peer topology tests ----

func TestCNCPeerTopology(t *testing.T) {
	c := newCache()
	c.cudnNames["backend-net"] = struct{}{}
	c.cudnNames["frontend-net"] = struct{}{}

	// Simulate two CUDNs connected by a CNC.
	selected := []string{"cudn:frontend-net", "cudn:backend-net"}
	for i, a := range selected {
		for j, b := range selected {
			if i != j {
				c.cncPeers[a] = appendUnique(c.cncPeers[a], b)
			}
		}
	}
	c.cncNetworks["my-cnc"] = selected

	peers := c.SearchPathPeers("cudn:frontend-net")
	if len(peers) != 1 || peers[0] != "cudn:backend-net" {
		t.Errorf("peers: got %v, want [cudn:backend-net]", peers)
	}

	// Delete CNC and verify peers are retracted.
	c.removeCNCLocked("my-cnc")
	peers = c.SearchPathPeers("cudn:frontend-net")
	if len(peers) != 0 {
		t.Errorf("after CNC delete: expected no peers, got %v", peers)
	}
}

// ---- UDN name length validation ----

func TestLongUDNNameSkipped(t *testing.T) {
	c := newCache()
	longName := "a-very-long-user-defined-network-name-that-exceeds-sixty-three-characters-long"
	if len(longName) <= maxDNSLabelLen {
		t.Skipf("test name %q is not > %d chars", longName, maxDNSLabelLen)
	}
	udn := newTestUDN("default", longName)
	c.OnUDNAdd(udn)

	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.udnNames["default/"+longName]; ok {
		t.Error("long-name UDN should have been skipped")
	}
}

// ---- UDN and CUDN registration tests ----

func TestUDNRegistration(t *testing.T) {
	c := newCache()
	udn := newTestUDN("default", "my-net")
	c.OnUDNAdd(udn)

	if !c.IsUDN("default/my-net") {
		t.Error("UDN not registered after OnUDNAdd")
	}
	c.OnUDNDelete(udn)
	if c.IsUDN("default/my-net") {
		t.Error("UDN still registered after OnUDNDelete")
	}
}

// ---- enforce-network-isolation tests ----

// newIsolatedPlugin creates a Plugin with EnforceIsolation=true (the production default).
func newIsolatedPlugin(zones []string) *Plugin {
	return &Plugin{
		Zones:            zones,
		cache:            newCache(),
		Next:             test.ErrorHandler(),
		EnforceIsolation: true,
	}
}

func TestIsolation_SameNetwork_Allowed(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	addPodToCache(p.cache, "default", "web-0", "default/my-net", []string{"10.128.1.5"})

	// Query originating from the same network (source IP = 10.128.1.5 itself).
	// In tests, dig comes from a ResponseWriter with a zero RemoteAddr, which
	// CanQuery treats as a default-network pod → allowed. That's tested below.
	// For true same-network, use a second pod as source.
	addPodToCache(p.cache, "default", "web-1", "default/my-net", []string{"10.128.1.6"})

	// web-1 (10.128.1.6) queries for web-0 (10.128.1.5) — same network.
	// Our test ResponseWriter sends queries from 127.0.0.1 (default-net) so
	// we verify directly via CanQuery.
	if !p.cache.CanQuery("10.128.1.6", "default/my-net") {
		t.Error("same-network query should be allowed")
	}
}

func TestIsolation_DifferentNetwork_Blocked(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	p.cache.udnNames["other/other-net"] = struct{}{}
	addPodToCache(p.cache, "default", "web-0", "default/my-net", []string{"10.128.1.5"})
	addPodToCache(p.cache, "other", "svc-0", "other/other-net", []string{"10.128.2.5"})

	// Pod on other-net tries to resolve my-net — should be blocked.
	if p.cache.CanQuery("10.128.2.5", "default/my-net") {
		t.Error("cross-network query should be blocked when isolation is on")
	}
}

func TestIsolation_CNCPeer_Allowed(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["ns-a/net-a"] = struct{}{}
	p.cache.udnNames["ns-b/net-b"] = struct{}{}
	// CNC connects net-a and net-b.
	p.cache.cncPeers["ns-a/net-a"] = []string{"ns-b/net-b"}
	p.cache.cncPeers["ns-b/net-b"] = []string{"ns-a/net-a"}

	addPodToCache(p.cache, "ns-a", "pod-a", "ns-a/net-a", []string{"10.128.1.5"})
	addPodToCache(p.cache, "ns-b", "pod-b", "ns-b/net-b", []string{"10.128.2.5"})

	// net-a pod queries net-b (direct CNC peer) — should be allowed.
	if !p.cache.CanQuery("10.128.1.5", "ns-b/net-b") {
		t.Error("CNC-connected peer query should be allowed")
	}

	// Add a third unconnected network — should still be blocked.
	p.cache.udnNames["ns-c/net-c"] = struct{}{}
	addPodToCache(p.cache, "ns-c", "pod-c", "ns-c/net-c", []string{"10.128.3.5"})
	if p.cache.CanQuery("10.128.1.5", "ns-c/net-c") {
		t.Error("non-peer network query should be blocked")
	}
}

func TestIsolation_DefaultNetworkPod_Blocked(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["default/my-net"] = struct{}{}
	addPodToCache(p.cache, "default", "web-0", "default/my-net", []string{"10.128.1.5"})

	// 192.0.2.1 is a source IP that is NOT in udnIPIndex at all — pure
	// default-network pod with no UDN attachments.
	// It must be blocked: it has no UDN membership to derive.
	if p.cache.CanQuery("192.0.2.1", "default/my-net") {
		t.Error("unknown source IP (no UDN pod) should be blocked from UDN addresses")
	}
}

// addPodWithDefaultIPToCache inserts a UDN pod whose default-network IP
// is also indexed (simulating what OVN-K does when the default interface is
// infrastructure-locked alongside the UDN primary interface).
func addPodWithDefaultIPToCache(c *Cache, namespace, name, nadKey string, udnIPs, defaultIPs []string) {
	udnList := make([]net.IP, 0, len(udnIPs))
	for _, s := range udnIPs {
		udnList = append(udnList, net.ParseIP(s))
	}
	defList := make([]net.IP, 0, len(defaultIPs))
	for _, s := range defaultIPs {
		defList = append(defList, net.ParseIP(s))
	}
	pod := &object.Pod{
		Name:       name,
		Namespace:  namespace,
		UDNIPs:     map[string][]net.IP{nadKey: udnList},
		DefaultIPs: defList,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range udnList {
		c.udnIPIndex[ip.String()] = pod
	}
	for _, ip := range defList {
		c.udnIPIndex[ip.String()] = pod
	}
	c.pods[namespace+"/"+name] = pod
}

func TestIsolation_UDNPodViaDefaultIP_Allowed(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["ns-a/net-a"] = struct{}{}

	// Pod has UDN IP 10.128.1.5 and default-network IP 10.244.1.10.
	// DNS traffic may arrive from either IP.
	addPodWithDefaultIPToCache(p.cache,
		"ns-a", "pod-a", "ns-a/net-a",
		[]string{"10.128.1.5"}, []string{"10.244.1.10"},
	)
	addPodToCache(p.cache, "ns-a", "pod-b", "ns-a/net-a", []string{"10.128.1.6"})

	// Query via UDN IP — allowed.
	if !p.cache.CanQuery("10.128.1.5", "ns-a/net-a") {
		t.Error("UDN pod queried via UDN IP should be allowed on its own network")
	}
	// Query via default-network IP — pod is still identified as a UDN pod.
	if !p.cache.CanQuery("10.244.1.10", "ns-a/net-a") {
		t.Error("UDN pod queried via default-network IP should be allowed on its own network")
	}
	// Default IP of the same pod must NOT grant access to a different network.
	p.cache.udnNames["ns-b/net-b"] = struct{}{}
	if p.cache.CanQuery("10.244.1.10", "ns-b/net-b") {
		t.Error("UDN pod default IP must not allow cross-network access")
	}
}

func TestIsolation_CUDN_SameNetwork_Allowed(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.cudnNames["blue-net"] = struct{}{}
	addPodToCache(p.cache, "bar", "api-0", "bar/blue-net", []string{"10.201.2.7"})
	addPodToCache(p.cache, "baz", "api-1", "baz/blue-net", []string{"10.201.2.8"})

	// Both pods are on the same CUDN — cross-namespace query is same-network.
	if !p.cache.CanQuery("10.201.2.7", "cudn:blue-net") {
		t.Error("same-CUDN query from different namespace should be allowed")
	}
}

func TestIsolation_CUDN_BlockedFromUDN(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["ns-a/net-a"] = struct{}{}
	p.cache.cudnNames["blue-net"] = struct{}{}
	addPodToCache(p.cache, "ns-a", "pod-a", "ns-a/net-a", []string{"10.128.1.5"})

	// net-a pod queries CUDN blue-net (no CNC) — should be blocked.
	if p.cache.CanQuery("10.128.1.5", "cudn:blue-net") {
		t.Error("UDN pod should not resolve CUDN without CNC when isolation is on")
	}
}

func TestIsolation_ForwardQuery_DefaultNet_ReturnsNXDOMAIN(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["ns-b/net-b"] = struct{}{}
	addPodToCache(p.cache, "ns-b", "pod-b", "ns-b/net-b", []string{"10.128.2.5"})

	// The test ResponseWriter sends from 127.0.0.1 which is not in any UDN
	// → default-network source → NXDOMAIN (blocked).
	msg := sendQuery(t, p, "10-128-2-5.net-b.ns-b.pod.cluster.local", dns.TypeA)
	if msg == nil || msg.Rcode != dns.RcodeNameError {
		t.Errorf("default-network source should get NXDOMAIN; got rcode %v", msg)
	}
}

func TestIsolation_ForwardQuery_SameUDN_ReturnsNOERROR(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local."})
	p.cache.udnNames["ns-a/net-a"] = struct{}{}
	// Both pods on the same UDN; one queries the other.
	addPodToCache(p.cache, "ns-a", "pod-a", "ns-a/net-a", []string{"10.128.1.5"})
	addPodToCache(p.cache, "ns-a", "pod-b", "ns-a/net-a", []string{"10.128.1.6"})

	// pod-a (10.128.1.5) queries pod-b (10.128.1.6) on the same UDN.
	if !p.cache.CanQuery("10.128.1.5", "ns-a/net-a") {
		t.Error("same-network query should be allowed")
	}
}

func TestIsolation_PTR_BlockedFromDefaultNet(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local.", "in-addr.arpa."})
	p.cache.udnNames["ns-b/net-b"] = struct{}{}
	_, subnetB, _ := net.ParseCIDR("10.129.0.0/16")
	p.cache.udnSubnets["ns-b/net-b"] = []*net.IPNet{subnetB}
	addPodToCache(p.cache, "ns-b", "pod-b", "ns-b/net-b", []string{"10.129.1.5"})

	// Test harness source = 127.0.0.1 = default-network → blocked.
	msg := sendQuery(t, p, "5.1.129.10.in-addr.arpa", dns.TypePTR)
	if msg == nil || msg.Rcode != dns.RcodeNameError {
		t.Errorf("default-net PTR should be NXDOMAIN; got %v", msg)
	}
}

func TestIsolation_PTR_BlockedFromUnconnectedUDN(t *testing.T) {
	p := newIsolatedPlugin([]string{"cluster.local.", "in-addr.arpa."})
	p.cache.udnNames["ns-a/net-a"] = struct{}{}
	p.cache.udnNames["ns-b/net-b"] = struct{}{}
	_, subnetB, _ := net.ParseCIDR("10.129.0.0/16")
	p.cache.udnSubnets["ns-b/net-b"] = []*net.IPNet{subnetB}
	addPodToCache(p.cache, "ns-a", "pod-a", "ns-a/net-a", []string{"10.128.1.5"})
	addPodToCache(p.cache, "ns-b", "pod-b", "ns-b/net-b", []string{"10.129.1.5"})

	// net-a pod queries net-b reverse → blocked (no CNC).
	if p.cache.CanQuery("10.128.1.5", "ns-b/net-b") {
		t.Fatal("net-a should not resolve net-b without CNC")
	}
}

// ---- ECS (EDNS0 Client Subnet) source-IP extraction tests ----

// TestExtractSourceIP_ECSPreferredOverNetworkLayer verifies that when a DNS
// query carries an EDNS0 Client Subnet option (injected by our TC BPF program),
// extractSourceIP returns the ECS address rather than the network-layer source.
func TestExtractSourceIP_ECSPreferredOverNetworkLayer(t *testing.T) {
	// Build a DNS query with an OPT RR carrying ECS for 10.200.0.10/32.
	req := new(dns.Msg)
	req.SetQuestion("example.cluster.local.", dns.TypeA)

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	ecs := new(dns.EDNS0_SUBNET)
	ecs.Code = dns.EDNS0SUBNET
	ecs.Family = 1 // IPv4
	ecs.SourceNetmask = 32
	ecs.SourceScope = 0
	ecs.Address = net.ParseIP("10.200.0.10").To4()
	opt.Option = append(opt.Option, ecs)
	req.Extra = append(req.Extra, opt)

	// The test ResponseWriter reports 127.0.0.1 as the remote address.
	state := request.Request{W: &test.ResponseWriter{}, Req: req}

	got := extractSourceIP(state)
	want := "10.200.0.10"
	if got != want {
		t.Errorf("extractSourceIP with ECS: got %q, want %q", got, want)
	}
}

func TestExtractSourceIP_FallsBackToNetworkLayer(t *testing.T) {
	// No ECS option — should fall back to the ResponseWriter's remote address.
	req := new(dns.Msg)
	req.SetQuestion("example.cluster.local.", dns.TypeA)

	state := request.Request{W: &test.ResponseWriter{}, Req: req}

	got := extractSourceIP(state)
	// test.ResponseWriter uses 10.240.0.1:40212 as the remote addr.
	if got == "" {
		t.Error("expected non-empty fallback source IP")
	}
	if got == "10.200.0.10" {
		t.Error("should not return ECS address when no ECS option present")
	}
}

func TestStripECS_RemovesSubnetOption(t *testing.T) {
	m := new(dns.Msg)
	m.SetReply(new(dns.Msg))

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	ecs := new(dns.EDNS0_SUBNET)
	ecs.Code = dns.EDNS0SUBNET
	ecs.Address = net.ParseIP("10.200.0.10").To4()
	opt.Option = append(opt.Option, ecs)
	m.Extra = append(m.Extra, opt)

	stripECS(m)

	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_SUBNET); ok {
				t.Error("ECS option still present after stripECS")
			}
		}
	}
}

func TestStripECS_KeepsOtherEdnsOptions(t *testing.T) {
	m := new(dns.Msg)
	m.SetReply(new(dns.Msg))

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	ecs := new(dns.EDNS0_SUBNET)
	ecs.Code = dns.EDNS0SUBNET
	ecs.Address = net.ParseIP("10.200.0.10").To4()
	nsid := new(dns.EDNS0_NSID)
	nsid.Code = dns.EDNS0NSID
	nsid.Nsid = "test"
	opt.Option = append(opt.Option, ecs, nsid)
	m.Extra = append(m.Extra, opt)

	stripECS(m)

	got := m.IsEdns0()
	if got == nil {
		t.Fatal("OPT RR removed entirely; should have kept NSID option")
	}
	if len(got.Option) != 1 {
		t.Errorf("expected 1 option after strip (NSID), got %d", len(got.Option))
	}
	if _, ok := got.Option[0].(*dns.EDNS0_NSID); !ok {
		t.Error("remaining option should be NSID")
	}
}
