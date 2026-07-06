# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage Dockerfile for building a custom CoreDNS binary that includes
# the ovn-kubernetes external plugin.
#
# Build from the repository root:
#
#   docker build -f plugin/coredns-ovn-kubernetes/Dockerfile \
#     -t ovn-kubernetes/coredns:dev .
#
# The resulting image is a drop-in replacement for registry.k8s.io/coredns/coredns
# with the ovn-kubernetes plugin added before the kubernetes plugin in the chain.
#
# For dns-operator / OpenShift-DNS integration:
#   Import the module with a blank import in your own CoreDNS main.go and add
#   the directive to your plugin.cfg before rebuilding:
#
#     ovn-kubernetes:github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes
#
# ---------------------------------------------------------------------------
# Stage 1 – build
# ---------------------------------------------------------------------------
FROM golang:1.25 AS builder

ARG COREDNS_VERSION=v1.13.1
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /build

# Clone CoreDNS at the exact version we compile against.
RUN git clone --depth=1 --branch=${COREDNS_VERSION} \
        https://github.com/coredns/coredns.git /coredns

# Copy the OVN-Kubernetes plugin module source and the go-controller package
# it depends on (types only — go-controller is never linked into the binary,
# only its CRD type definitions are).
COPY plugin/coredns-ovn-kubernetes/ /ovnk-plugin/
COPY go-controller/                 /go-controller/

WORKDIR /coredns

# Disable any go.work from the build context — CoreDNS has its own go.mod.
ENV GOWORK=off

# ---------------------------------------------------------------------------
# Insert our plugin into plugin.cfg immediately before the kubernetes entry.
# The generator reads this file to produce:
#   core/plugin/zplugin.go        – blank imports
#   core/dnsserver/zdirectives.go – ordered directive slice
# ---------------------------------------------------------------------------
RUN sed -i \
    's|^kubernetes:kubernetes$|ovn-kubernetes:github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes\nkubernetes:kubernetes|' \
    plugin.cfg

# Add replace directives so the build uses our local module copies instead of
# trying to fetch unpublished versions from the module proxy.
RUN go mod edit \
    -replace=github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes=/ovnk-plugin \
    -replace=github.com/ovn-kubernetes/ovn-kubernetes/go-controller=/go-controller \
    -require=github.com/ovn-kubernetes/ovn-kubernetes/plugin/coredns-ovn-kubernetes@v0.0.0

# Regenerate zplugin.go (blank imports) and zdirectives.go (ordered list).
RUN go generate coredns.go

# Resolve the full dependency graph.  The replace directives satisfy the
# go-controller requirement transitively; only published deps are fetched.
RUN go mod tidy

# Build.  CGO_ENABLED=0 produces a fully static binary for the distroless base.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -ldflags="-s -w \
        -X github.com/coredns/coredns/coremain.gitVersion=${COREDNS_VERSION}+ovnk" \
      -o /bin/coredns \
      .

# ---------------------------------------------------------------------------
# Stage 2 – runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /bin/coredns /coredns

USER nonroot:nonroot
EXPOSE 53 53/udp 9153

ENTRYPOINT ["/coredns"]
