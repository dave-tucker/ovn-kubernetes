# ovn-kubernetes CoreDNS Plugin

An external CoreDNS plugin that serves DNS records for pods on
[OVN-Kubernetes](https://ovn-kubernetes.io) User Defined Networks (UDN) and
Cluster User Defined Networks (CUDN).

## Overview

The standard CoreDNS `kubernetes` plugin resolves pod IPs from
`pod.Status.PodIP`.  Pods on a primary UDN hold their cluster IP in the
`k8s.ovn.org/pod-networks` annotation, which the `kubernetes` plugin ignores.
This plugin fills that gap by:

- Serving **A / AAAA** records for every UDN and CUDN IP a pod carries
- Serving **PTR** records for UDN / CUDN IPs in the `in-addr.arpa` /
  `ip6.arpa` reverse zones
- Serving **hostname + subdomain** records for pods with `spec.hostname` and
  `spec.subdomain` set on a UDN / CUDN
- Implementing CoreDNS **autopath** so that UDN pods resolve short service
  names without a full FQDN (`my-service` → `my-service.my-net.ns.svc.cluster.local`)

## DNS Name Formats

| Record type | Format |
|---|---|
| UDN pod IP | `<dashed-ip>.<udn-name>.<namespace>.pod.cluster.local` |
| CUDN pod IP | `<dashed-ip>.<cudn-name>.pod.cluster.local` |
| UDN hostname+subdomain | `<hostname>.<subdomain>.<udn-name>.<namespace>.svc.cluster.local` |
| CUDN hostname+subdomain | `<hostname>.<subdomain>.<cudn-name>.svc.cluster.local` |
| PTR (UDN) | `5.1.128.10.in-addr.arpa.` → `10-128-1-5.my-net.default.pod.cluster.local.` |
| PTR (CUDN) | `7.2.201.10.in-addr.arpa.` → `10-201-2-7.blue-net.pod.cluster.local.` |

`<dashed-ip>` replaces dots (IPv4) or colons (IPv6) with dashes.  A double
dash (`--`) encodes the IPv6 `::` abbreviation.

## Corefile Configuration

```corefile
cluster.local {
    ovn-kubernetes
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods verified
    }
    cache 30
    loop
    reload
    loadbalance
}

in-addr.arpa {
    ovn-kubernetes
    kubernetes cluster.local in-addr.arpa ip6.arpa
}

ip6.arpa {
    ovn-kubernetes
    kubernetes cluster.local in-addr.arpa ip6.arpa
}
```

**`ovn-kubernetes` must appear before `kubernetes` in every stanza.**

The plugin takes no arguments; all data is auto-discovered via the Kubernetes
API (in-cluster config by default, or `$KUBECONFIG` for local development).

## Autopath Search Path

For a pod in namespace `foo` on primary UDN `my-net` and secondary CUDN
`blue-net`, connected to CUDN `backend-net` via `ClusterNetworkConnect`:

```
my-net.foo.svc.cluster.local    # primary UDN
blue-net.svc.cluster.local      # secondary CUDN
backend-net.svc.cluster.local   # CNC peer (one hop only)
foo.svc.cluster.local           # standard Kubernetes fallback
svc.cluster.local
cluster.local
""
```

## Building

The plugin must be compiled into a custom CoreDNS binary:

```bash
cd plugin/coredns-ovn-kubernetes
go mod tidy          # first time only
make build           # produces bin/coredns
make test            # run unit tests
make image           # build container image (requires Docker)
```

The `cmd/coredns/main.go` blank-imports both this plugin and the standard
CoreDNS plugin suite.

## RBAC

The plugin needs read access to the following resources:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["k8s.ovn.org"]
    resources:
      - userdefinednetworks
      - clusteruserdefinednetworks
      - clusternetworkconnects
    verbs: ["get", "list", "watch"]
```

## Known Limitations

- **UDN / CUDN names longer than 63 characters** are skipped (DNS label limit).
  A warning is logged.  The correct fix is to add `MaxLength=63` validation to
  the UDN and CUDN CRDs.
- **Service records** (Phase 5) are not yet implemented; they are blocked on
  the UDN service load-balancer work.
- **Autopath** source-IP mapping is subject to a short race window if a pod IP
  is immediately reused after deletion.

## Implementation Phases

| Phase | Feature | Status |
|---|---|---|
| 1 | A / AAAA pod-IP records | ✅ |
| 2 | PTR reverse records | ✅ |
| 3 | Autopath search path | ✅ |
| 4 | Hostname + subdomain records | ✅ |
| 5 | Service ClusterIP records | ⏳ blocked on UDN service LB |

## See Also

- [OKEP: CoreDNS Plugin for UDN](../../docs/okeps/okep-XXXX-udn-coredns-plugin.md)
- [User Defined Networks design](../../docs/design/user-defined-network.md)
- [CoreDNS external plugin guide](https://coredns.io/explugins/)
