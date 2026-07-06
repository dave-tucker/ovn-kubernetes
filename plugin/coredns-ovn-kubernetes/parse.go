// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovnkubernetes

import (
	"net"
	"strings"
)

// queryKind identifies what kind of UDN DNS record a query is asking for.
type queryKind int

const (
	// queryUnknown means the name does not match any UDN/CUDN format; the
	// plugin must fall through to the next handler.
	queryUnknown queryKind = iota
	// queryUDNPodIP is an A/AAAA query for a namespace-scoped UDN pod IP:
	//   <dashed-ip>.<udn-name>.<namespace>.pod.<zone>
	queryUDNPodIP
	// queryCUDNPodIP is an A/AAAA query for a cluster-scoped CUDN pod IP:
	//   <dashed-ip>.<cudn-name>.pod.<zone>
	queryCUDNPodIP
	// queryUDNHostname is an A/AAAA query for a UDN pod hostname+subdomain:
	//   <hostname>.<subdomain>.<udn-name>.<namespace>.svc.<zone>
	queryUDNHostname
	// queryCUDNHostname is an A/AAAA query for a CUDN pod hostname+subdomain:
	//   <hostname>.<subdomain>.<cudn-name>.svc.<zone>
	queryCUDNHostname
)

// parsedQuery holds the structured fields extracted from a DNS query name.
type parsedQuery struct {
	Kind queryKind

	// IP is the parsed net.IP for pod-IP queries (queryUDNPodIP, queryCUDNPodIP).
	// Nil for hostname queries.
	IP net.IP

	// NetworkName is the UDN or CUDN name label extracted from the query.
	NetworkName string

	// Namespace is the namespace label for UDN queries.  Empty for CUDN queries.
	Namespace string

	// Hostname and Subdomain are set for hostname+subdomain queries.
	Hostname  string
	Subdomain string
}

// parseQuery parses a fully-qualified DNS name (without the trailing dot) after
// stripping the zone suffix.  zone must be the bare zone without a trailing dot
// (e.g. "cluster.local").
//
// Returns (parsedQuery{Kind: queryUnknown}, nil) when the name does not match
// any UDN/CUDN format.  The caller is responsible for falling through to the
// next plugin in that case.
func parseQuery(qname, zone string) parsedQuery {
	// Strip the zone and the separator dot.
	suffix := "." + zone + "."
	if !strings.HasSuffix(qname, suffix) {
		// Try without trailing dot (qname already has one stripped by caller).
		suffix = "." + zone
		if !strings.HasSuffix(qname, suffix) {
			return parsedQuery{Kind: queryUnknown}
		}
	}
	relative := strings.TrimSuffix(qname, suffix)

	labels := strings.Split(relative, ".")
	n := len(labels)
	if n < 3 {
		return parsedQuery{Kind: queryUnknown}
	}

	recordType := labels[n-1] // "pod" or "svc"

	switch recordType {
	case "pod":
		switch n {
		case 4:
			// <dashed-ip>.<udn-name>.<namespace>.pod
			ip := dashedToIP(labels[0])
			if ip == nil {
				return parsedQuery{Kind: queryUnknown}
			}
			return parsedQuery{
				Kind:        queryUDNPodIP,
				IP:          ip,
				NetworkName: labels[1],
				Namespace:   labels[2],
			}
		case 3:
			// <dashed-ip>.<cudn-name>.pod
			ip := dashedToIP(labels[0])
			if ip == nil {
				return parsedQuery{Kind: queryUnknown}
			}
			return parsedQuery{
				Kind:        queryCUDNPodIP,
				IP:          ip,
				NetworkName: labels[1],
			}
		}
	case "svc":
		switch n {
		case 5:
			// <hostname>.<subdomain>.<udn-name>.<namespace>.svc
			return parsedQuery{
				Kind:        queryUDNHostname,
				Hostname:    labels[0],
				Subdomain:   labels[1],
				NetworkName: labels[2],
				Namespace:   labels[3],
			}
		case 4:
			// <hostname>.<subdomain>.<cudn-name>.svc
			return parsedQuery{
				Kind:        queryCUDNHostname,
				Hostname:    labels[0],
				Subdomain:   labels[1],
				NetworkName: labels[2],
			}
		}
	}

	return parsedQuery{Kind: queryUnknown}
}

// dashedToIP converts a dashed-IP string ("10-128-1-5" or "2001-db8--1") back
// to a net.IP.  Returns nil if the string is not a valid dashed IP address.
func dashedToIP(dashed string) net.IP {
	// IPv4: four numeric groups separated by dashes.
	// IPv6: groups separated by dashes; consecutive dashes stand for "::".
	// Strategy: replace dashes with dots and try IPv4 first; then replace
	// with colons for IPv6.

	// IPv4 attempt.
	candidate := strings.ReplaceAll(dashed, "-", ".")
	if ip := net.ParseIP(candidate); ip != nil {
		return ip
	}

	// IPv6 attempt: single dash → colon, double dash → double colon.
	// "2001-db8--1" → "2001:db8::1"
	candidate = strings.ReplaceAll(dashed, "--", "::")
	candidate = strings.ReplaceAll(candidate, "-", ":")
	// Handle leading/trailing double-colon that may have an extra colon.
	if ip := net.ParseIP(candidate); ip != nil {
		return ip
	}

	return nil
}

// ipToDashed converts a net.IP to its dashed DNS label form.
// IPv4: "10.128.1.5" → "10-128-1-5"
// IPv6: "2001:db8::1" → "2001-db8--1"
func ipToDashed(ip net.IP) string {
	s := ip.String()
	if ip.To4() != nil {
		return strings.ReplaceAll(s, ".", "-")
	}
	// IPv6: replace "::" with "--" first so single colons map to single dashes.
	s = strings.ReplaceAll(s, "::", "--")
	s = strings.ReplaceAll(s, ":", "-")
	return s
}

// udnNADKey returns the NAD annotation key for a namespace-scoped UDN.
func udnNADKey(namespace, udnName string) string {
	return namespace + "/" + udnName
}
