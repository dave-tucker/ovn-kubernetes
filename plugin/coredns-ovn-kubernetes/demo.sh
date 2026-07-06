#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0
#
# demo.sh — asciinema demo script for the ovn-kubernetes CoreDNS plugin.
#
# Covers:
#   1. Cluster overview
#   2. UDN — A / AAAA records and PTR
#   3. CUDN — primary cluster-scoped network across two namespaces
#   4. Hostname + subdomain records
#   5. DNS isolation — same hostname/subdomain in two different UDNs
#   6. DNS transparency — cross-network lookups succeed by design
#   7. Why we don't restrict cross-network DNS by default
#
# Record with:
#   asciinema rec --overwrite \
#     --title "OVN-Kubernetes UDN CoreDNS Plugin" \
#     -c ./demo.sh udn-coredns-demo.cast
#
set -euo pipefail

# ── env ───────────────────────────────────────────────────────────────────────

CLUSTER=udn-dns
kind export kubeconfig --name "$CLUSTER" --kubeconfig /tmp/demo-kubeconfig.yaml 2>/dev/null
export KUBECONFIG=/tmp/demo-kubeconfig.yaml
K="/home/dave/.local/share/mise/installs/kubectl/1.36.1/kubectl"

# ── helpers ───────────────────────────────────────────────────────────────────

say()    { printf '\e[1;36m# %s\e[0m\n' "$*"; sleep 0.5; }
run() {
  # Show the command with a short "kubectl" label instead of the full path.
  local display
  display=$(echo "$*" | sed "s|${K}|kubectl|g; s|  *| |g")
  printf '\e[1;33m$ %s\e[0m\n' "$display"
  sleep 0.7
  eval "$*"
  sleep 0.9
}
banner() {
  echo
  printf '\e[1;35m══════════════════════════════════════════════════════\e[0m\n'
  printf '\e[1;35m  %s\e[0m\n' "$*"
  printf '\e[1;35m══════════════════════════════════════════════════════\e[0m\n'
  echo; sleep 0.6
}
note() {  # yellow inline note — no command, just commentary
  printf '\e[0;33m  ↳ %s\e[0m\n' "$*"; sleep 0.8
}
pause() { sleep "${1:-1.2}"; }

# ── preflight: ensure all demo objects exist ──────────────────────────────────

wait_pod_annotated() {  # namespace pod → UDN IP (CIDR form)
  local ns=$1 pod=$2
  for _ in $(seq 1 20); do
    local annot
    annot=$($K get pod "$pod" -n "$ns" --request-timeout=5s \
      -o jsonpath='{.metadata.annotations.k8s\.ovn\.org/pod-networks}' 2>/dev/null || true)
    local ip
    ip=$(python3 -c "
import json, sys
d = json.loads('''${annot}''')
for k, v in d.items():
    if k != 'default':
        print(v['ip_addresses'][0].split('/')[0])
        break
" 2>/dev/null || true)
    [ -n "$ip" ] && echo "$ip" && return
    sleep 5
  done
  echo ""
}

# UDN namespace + network
if ! $K get ns udn-test --request-timeout=5s &>/dev/null; then
  $K apply -f - --request-timeout=15s <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: udn-test
  labels:
    k8s.ovn.org/primary-user-defined-network: test-net
---
apiVersion: k8s.ovn.org/v1
kind: UserDefinedNetwork
metadata:
  name: test-net
  namespace: udn-test
spec:
  topology: Layer2
  layer2:
    role: Primary
    subnets: ["10.200.0.0/24"]
YAML
  sleep 10
fi

for pod in web-a web-b; do
  $K get pod "$pod" -n udn-test --request-timeout=5s &>/dev/null && continue
  extra=""
  [ "$pod" = "web-b" ] && extra=$'\n  hostname: myhost\n  subdomain: mysvc'
  $K apply --request-timeout=10s -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  namespace: udn-test
spec:${extra}
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.10
YAML
done

# CUDN namespaces + network
for ns in ns-alice ns-bob; do
  $K get ns "$ns" --request-timeout=5s &>/dev/null && continue
  $K apply --request-timeout=10s -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $ns
  labels:
    k8s.ovn.org/primary-user-defined-network: ""
YAML
done

if ! $K get cudn shared-net --request-timeout=5s &>/dev/null; then
  $K apply --request-timeout=10s -f - <<'YAML'
apiVersion: k8s.ovn.org/v1
kind: ClusterUserDefinedNetwork
metadata:
  name: shared-net
spec:
  namespaceSelector:
    matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: In
        values: [ns-alice, ns-bob]
  network:
    topology: Layer2
    layer2:
      role: Primary
      subnets: ["10.201.0.0/24"]
YAML
  sleep 10
fi

for ns_pod in "ns-alice/alice-pod" "ns-bob/bob-pod"; do
  ns=${ns_pod%/*}; pod=${ns_pod#*/}
  $K get pod "$pod" -n "$ns" --request-timeout=5s &>/dev/null && continue
  $K run "$pod" -n "$ns" --image=registry.k8s.io/pause:3.10 --restart=Never \
    --request-timeout=10s
done

# Isolation demo namespace
if ! $K get ns ns-red --request-timeout=5s &>/dev/null; then
  $K apply --request-timeout=15s -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: ns-red
  labels:
    k8s.ovn.org/primary-user-defined-network: red-net
---
apiVersion: k8s.ovn.org/v1
kind: UserDefinedNetwork
metadata:
  name: red-net
  namespace: ns-red
spec:
  topology: Layer2
  layer2:
    role: Primary
    subnets: ["10.202.0.0/24"]
YAML
  sleep 10
fi

if ! $K get pod myhost -n ns-red --request-timeout=5s &>/dev/null; then
  $K apply --request-timeout=10s -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: myhost
  namespace: ns-red
spec:
  hostname: myhost
  subdomain: mysvc
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.10
YAML
fi

# dnstest exec pod (default network)
if ! $K get pod dnstest -n default --request-timeout=5s &>/dev/null; then
  $K run dnstest -n default \
    --image=registry.k8s.io/e2e-test-images/agnhost:2.53 \
    --command -- sleep 600 --request-timeout=10s 2>/dev/null || true
fi

# udn-dig — exec pod INSIDE the udn-test UDN, so its DNS queries originate
# from its UDN primary IP (10.200.x.x). Used to demo cross-UDN isolation.
if ! $K get pod udn-dig -n udn-test --request-timeout=5s &>/dev/null; then
  $K run udn-dig -n udn-test \
    --image=registry.k8s.io/e2e-test-images/agnhost:2.53 \
    --command -- sleep 600 --request-timeout=10s 2>/dev/null || true
fi

# Wait for pods
$K wait pod web-a web-b udn-dig -n udn-test --for=condition=Ready --timeout=90s \
  --request-timeout=10s &>/dev/null || true
$K wait pod alice-pod -n ns-alice --for=condition=Ready --timeout=90s \
  --request-timeout=10s &>/dev/null || true
$K wait pod bob-pod -n ns-bob --for=condition=Ready --timeout=90s \
  --request-timeout=10s &>/dev/null || true
$K wait pod myhost -n ns-red --for=condition=Ready --timeout=90s \
  --request-timeout=10s &>/dev/null || true
$K wait pod dnstest -n default --for=condition=Ready --timeout=90s \
  --request-timeout=10s &>/dev/null || true

# Resolve IPs
WEB_A_IP=$(wait_pod_annotated udn-test web-a)
WEB_B_IP=$(wait_pod_annotated udn-test web-b)
ALICE_IP=$(wait_pod_annotated ns-alice alice-pod)
BOB_IP=$(wait_pod_annotated ns-bob   bob-pod)
RED_IP=$(wait_pod_annotated  ns-red   myhost)

WEB_A_D="${WEB_A_IP//./-}"
WEB_B_D="${WEB_B_IP//./-}"
ALICE_D="${ALICE_IP//./-}"
BOB_D="${BOB_IP//./-}"
RED_D="${RED_IP//./-}"

WEB_A_REV=$(echo "$WEB_A_IP" | awk -F. '{print $4"."$3"."$2"."$1}')
ALICE_REV=$(echo "$ALICE_IP" | awk -F. '{print $4"."$3"."$2"."$1}')

DNS=$($K get svc kube-dns -n kube-system --request-timeout=5s \
  -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
DIG="$K exec dnstest -n default --request-timeout=15s -- dig"

# ── THE DEMO ─────────────────────────────────────────────────────────────────

clear

banner "OVN-Kubernetes CoreDNS Plugin — live demo"

say "This cluster runs OVN-Kubernetes with UDN + CUDN support."
say "CoreDNS has been replaced with a custom build that includes the ovn-kubernetes plugin."
pause

# ── 1. Cluster overview ───────────────────────────────────────────────────────

banner "1. Cluster overview"

run "$K get nodes --request-timeout=10s"

say "Plugin is compiled into CoreDNS via plugin.cfg + go generate:"
run "$K -n kube-system exec deploy/coredns --request-timeout=10s -- \
  /coredns -plugins 2>&1 | grep -E 'ovn-kubernetes|^kubernetes'"

say "The ovn-kubernetes directive sits before kubernetes in the Corefile:"
run "$K -n kube-system get configmap coredns --request-timeout=5s \
  -o jsonpath='{.data.Corefile}' | grep -A1 'cluster.local'"

# ── 2. UDN — UserDefinedNetwork ───────────────────────────────────────────────

banner "2. UDN — namespace-scoped UserDefinedNetwork"

say "Namespace 'udn-test' runs on a primary Layer2 UDN (10.200.0.0/24):"
run "$K get udn test-net -n udn-test --request-timeout=10s \
  -o custom-columns='NAME:.metadata.name,TOPO:.spec.topology,SUBNET:.spec.layer2.subnets[0]'"

say "Two pods on this UDN: web-a ($WEB_A_IP) and web-b ($WEB_B_IP)."
say "OVN-K records UDN IPs in the k8s.ovn.org/pod-networks annotation:"
run "$K get pod web-a -n udn-test --request-timeout=10s \
  -o jsonpath='{.metadata.annotations.k8s\.ovn\.org/pod-networks}' | python3 -m json.tool"

echo
say "DNS format:  <dashed-ip>.<udn-name>.<namespace>.pod.cluster.local"
pause

run "$DIG @$DNS ${WEB_A_D}.test-net.udn-test.pod.cluster.local A +short +time=5"
run "$DIG @$DNS ${WEB_B_D}.test-net.udn-test.pod.cluster.local A +short +time=5"

say "PTR format:  <reversed-ip>.in-addr.arpa"
run "$DIG @$DNS ${WEB_A_REV}.in-addr.arpa PTR +short +time=5"

say "Unknown UDN name → falls through to kubernetes plugin → NXDOMAIN:"
run "$DIG @$DNS ${WEB_A_D}.ghost-net.udn-test.pod.cluster.local A \
  +noall +comments +time=5 2>&1 | grep 'status:'"

# ── 3. CUDN — ClusterUserDefinedNetwork ───────────────────────────────────────

banner "3. CUDN — primary ClusterUserDefinedNetwork (cluster-scoped)"

say "A ClusterUserDefinedNetwork spans multiple namespaces via namespaceSelector."
say "shared-net is the primary network for both ns-alice and ns-bob:"
run "$K get cudn shared-net --request-timeout=10s \
  -o custom-columns='NAME:.metadata.name,TOPO:.spec.network.topology,SUBNET:.spec.network.layer2.subnets[0]'"

say "alice-pod ($ALICE_IP) in ns-alice, bob-pod ($BOB_IP) in ns-bob — same network:"
run "$K get pods -n ns-alice -n ns-bob --request-timeout=10s -o wide 2>&1 | \
  grep -E 'alice|bob|NAME'"

echo
say "Key difference from UDN: the CUDN name is cluster-unique, so the namespace"
say "is NOT part of the DNS label."
say ""
say "  UDN format:   <ip>.<udn-name>.<namespace>.pod.cluster.local"
say "  CUDN format:  <ip>.<cudn-name>.pod.cluster.local           ← no namespace"
pause 2

say "Both alice-pod and bob-pod resolve via the same DNS pattern:"
run "$DIG @$DNS ${ALICE_D}.shared-net.pod.cluster.local A +short +time=5"
run "$DIG @$DNS ${BOB_D}.shared-net.pod.cluster.local A +short +time=5"

say "PTR for alice-pod — resolves without a namespace component:"
run "$DIG @$DNS ${ALICE_REV}.in-addr.arpa PTR +short +time=5"

# ── 4. Hostname + subdomain ───────────────────────────────────────────────────

banner "4. Hostname + subdomain records"

say "web-b has spec.hostname=myhost and spec.subdomain=mysvc on test-net:"
say "  UDN:   myhost.mysvc.<udn-name>.<namespace>.svc.cluster.local"
say "  CUDN:  myhost.mysvc.<cudn-name>.svc.cluster.local"
pause

run "$DIG @$DNS myhost.mysvc.test-net.udn-test.svc.cluster.local A +short +time=5"

# ── 5. DNS isolation ──────────────────────────────────────────────────────────

banner "5. DNS isolation — same hostname/subdomain in two different UDNs"

say "ns-red has its own primary UDN (red-net, 10.202.0.0/24)."
say "It also has a pod named 'myhost' with hostname=myhost, subdomain=mysvc."
say ""
say "Both UDNs have a pod claiming hostname=myhost / subdomain=mysvc."
say "The scoped label guarantees they resolve to different IPs:"
pause 2

say "myhost.mysvc in test-net/udn-test:"
run "$DIG @$DNS myhost.mysvc.test-net.udn-test.svc.cluster.local A +short +time=5"

say "myhost.mysvc in red-net/ns-red:"
run "$DIG @$DNS myhost.mysvc.red-net.ns-red.svc.cluster.local A +short +time=5"

note "web-b (test-net) and myhost (red-net) have different IPs: $WEB_B_IP vs $RED_IP"
note "The <udn-name>.<namespace> label makes collisions structurally impossible."
note "For CUDNs: <cudn-name> alone is sufficient because names are cluster-unique."
pause 2

# ── 6. DNS isolation — live demo ─────────────────────────────────────────────

banner "6. DNS isolation — live queries"

say "Rules (isolation is ON by default; use disable-network-isolation to opt out):"
pause
cat <<'RULES'  # default behaviour; use disable-network-isolation to opt out
  ┌──────────────────────┬───────────────────┬───────────────────────┐
  │  Querying pod        │  Target network   │  Result               │
  ├──────────────────────┼───────────────────┼───────────────────────┤
  │  default-network     │  any UDN / CUDN   │  NXDOMAIN (blocked)   │
  │  UDN A               │  UDN A            │  NOERROR  (same net)  │
  │  UDN A               │  UDN B (CNC peer) │  NOERROR  (connected) │
  │  UDN A               │  UDN C (no CNC)   │  NXDOMAIN (blocked)   │
  │  CUDN X              │  CUDN X           │  NOERROR  (same net)  │
  │  CUDN X              │  UDN A (no CNC)   │  NXDOMAIN (blocked)   │
  └──────────────────────┴───────────────────┴───────────────────────┘
RULES
pause 2

say "Let's prove it with live queries."
pause

say "1) Default-network pod (dnstest) trying to resolve a UDN IP — BLOCKED:"
note "source UDN = nil (dnstest has no primary UDN) → cannot resolve UDN records"
run "$DIG @$DNS ${WEB_A_D}.test-net.udn-test.pod.cluster.local A +noall +comments +time=5 \
  2>&1 | grep 'status:'"

say "2) Default-network pod trying to resolve a CUDN IP — also BLOCKED:"
run "$DIG @$DNS ${ALICE_D}.shared-net.pod.cluster.local A +noall +comments +time=5 \
  2>&1 | grep 'status:'"

pause 1
say "3) UDN pod (udn-dig, on test-net) resolving its OWN network — ALLOWED:"
note "source UDN = udn-test/test-net == dest UDN → allowed"
run "$K exec udn-dig -n udn-test --request-timeout=15s -- \
  dig @$DNS ${WEB_A_D}.test-net.udn-test.pod.cluster.local A +short +time=5"

pause 1
say "4) UDN pod (test-net) resolving a DIFFERENT UDN (red-net, no CNC) — BLOCKED:"
note "source UDN = udn-test/test-net, dest = ns-red/red-net, no CNC → NXDOMAIN"
run "$K exec udn-dig -n udn-test --request-timeout=15s -- \
  dig @$DNS ${RED_D}.red-net.ns-red.pod.cluster.local A +noall +comments +time=5 \
  2>&1 | grep 'status:'"

pause 1
say "5) UDN pod (test-net) resolving a CUDN (shared-net, no CNC) — BLOCKED:"
cat <<CANQUERY
  sourceUDNs(“${WEB_A_IP}”) = ["udn-test/test-net"]
  targetNetKey            = "cudn:shared-net"
  same network?           no
  CNC peers of test-net?  [] (no CNC)
  result                  NXDOMAIN
CANQUERY
run "$K exec udn-dig -n udn-test --request-timeout=15s -- \
  dig @$DNS ${ALICE_D}.shared-net.pod.cluster.local A +noall +comments +time=5 \
  2>&1 | grep 'status:'"

pause 1
note "The data-plane already blocks cross-network traffic."
note "DNS isolation adds a second line of defence — prevents IP enumeration."
note "NXDOMAIN (not REFUSED) keeps client retry behaviour consistent."
pause 2

say "To opt out (transparent DNS), add disable-network-isolation to the Corefile:"
cat <<'OPTOUT'
  cluster.local {
      ovn-kubernetes {
          disable-network-isolation
      }
      kubernetes cluster.local in-addr.arpa ip6.arpa { pods insecure }
      ...
  }
OPTOUT
pause 2

# ── 8. Fallback ───────────────────────────────────────────────────────────────

banner "8. Fallback — default-network DNS unchanged"

say "Every query that doesn't match a UDN/CUDN pattern falls through"
say "to the kubernetes plugin — no disruption to existing workloads:"
pause

run "$DIG @$DNS kubernetes.default.svc.cluster.local A +short +time=5"
run "$DIG @$DNS kube-dns.kube-system.svc.cluster.local A +short +time=5"

# ── done ─────────────────────────────────────────────────────────────────────

banner "Summary"
cat <<'SUMMARY'
  Record types implemented
  ────────────────────────
  UDN  A/AAAA   <dashed-ip>.<udn-name>.<namespace>.pod.cluster.local
  UDN  PTR      <reversed>.in-addr.arpa / ip6.arpa
  UDN  hostname <host>.<sub>.<udn-name>.<namespace>.svc.cluster.local

  CUDN A/AAAA   <dashed-ip>.<cudn-name>.pod.cluster.local    (no namespace)
  CUDN PTR      same reverse zones
  CUDN hostname <host>.<sub>.<cudn-name>.svc.cluster.local

  Autopath      UDN-aware search path; CNC peers included (1 hop)

  Plugin source:  plugin/coredns-ovn-kubernetes/
  OKEP:           docs/okeps/okep-XXXX-udn-coredns-plugin.md
  Build image:    make -C plugin/coredns-ovn-kubernetes image
SUMMARY
pause 3
