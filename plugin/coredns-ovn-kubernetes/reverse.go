// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovnkubernetes

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// extractIPFromPTR converts a PTR query name to its corresponding net.IP.
// Supports both in-addr.arpa (IPv4) and ip6.arpa (IPv6) formats.
// Returns nil if the name is not a valid reverse-DNS name.
func extractIPFromPTR(qname string) net.IP {
	qname = strings.ToLower(dns.Fqdn(qname))

	if strings.HasSuffix(qname, ".in-addr.arpa.") {
		return extractIPv4FromPTR(qname)
	}
	if strings.HasSuffix(qname, ".ip6.arpa.") {
		return extractIPv6FromPTR(qname)
	}
	return nil
}

// extractIPv4FromPTR parses an IPv4 PTR name ("5.1.128.10.in-addr.arpa.") →
// net.IP("10.128.1.5").
func extractIPv4FromPTR(qname string) net.IP {
	s := strings.TrimSuffix(qname, ".in-addr.arpa.")
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	// Reverse the octets.
	rev := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
	return net.ParseIP(rev)
}

// extractIPv6FromPTR parses an IPv6 PTR name (nibble format) → net.IP.
// Example: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
func extractIPv6FromPTR(qname string) net.IP {
	s := strings.TrimSuffix(qname, ".ip6.arpa.")
	nibbles := strings.Split(s, ".")
	if len(nibbles) != 32 {
		return nil
	}
	// Reverse the nibbles and reassemble into a colon-hex string.
	hexStr := ""
	for i := len(nibbles) - 1; i >= 0; i-- {
		hexStr += nibbles[i]
		if i > 0 && (len(nibbles)-i)%4 == 0 {
			hexStr += ":"
		}
	}
	return net.ParseIP(hexStr)
}

// ptrTarget builds the DNS PTR target name for the given IP and network.
// For a UDN:  "<dashed-ip>.<udn-name>.<namespace>.pod.<zone>."
// For a CUDN: "<dashed-ip>.<cudn-name>.pod.<zone>."
func ptrTarget(ip net.IP, networkKey, zone string, isCUDN bool) string {
	dashed := ipToDashed(ip)
	if isCUDN {
		name := strings.TrimPrefix(networkKey, networkKeyPrefixCUDN)
		return dns.Fqdn(dashed + "." + name + ".pod." + zone)
	}
	// UDN key is "namespace/udn-name"
	parts := strings.SplitN(networkKey, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	ns, udnName := parts[0], parts[1]
	return dns.Fqdn(dashed + "." + udnName + "." + ns + ".pod." + zone)
}
