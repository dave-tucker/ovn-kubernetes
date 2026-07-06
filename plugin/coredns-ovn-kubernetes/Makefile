# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0

REPO_ROOT   := $(shell git rev-parse --show-toplevel)
BINARY      ?= $(REPO_ROOT)/plugin/coredns-ovn-kubernetes/bin/coredns
IMAGE_REPO  ?= ovn-kubernetes/coredns
IMAGE_TAG   ?= dev
IMAGE       := $(IMAGE_REPO):$(IMAGE_TAG)

# CoreDNS version to clone in the Docker build.
# Keep in sync with the version in go.mod.
COREDNS_VERSION ?= v1.13.1

.PHONY: all build test lint image kind-load clean

all: build

## build: Build a local CoreDNS binary for development/testing.
##        Uses the go.work workspace (go-controller resolved locally).
build:
	mkdir -p $(dir $(BINARY))
	cd $(REPO_ROOT) && go build \
		-ldflags="-X github.com/coredns/coredns/coremain.gitVersion=$(COREDNS_VERSION)+ovnk-dev" \
		-o $(BINARY) \
		./plugin/coredns-ovn-kubernetes/cmd/coredns

## test: Run unit tests for the plugin package.
test:
	cd $(REPO_ROOT) && go test -v -count=1 ./plugin/coredns-ovn-kubernetes/...

## lint: Run golangci-lint.
lint:
	cd $(REPO_ROOT)/plugin/coredns-ovn-kubernetes && golangci-lint run ./...

## image: Build the production container image via the multi-stage Dockerfile.
##        Build context is the repository root so go-controller is included.
image:
	docker build \
		--build-arg COREDNS_VERSION=$(COREDNS_VERSION) \
		-f $(REPO_ROOT)/plugin/coredns-ovn-kubernetes/Dockerfile \
		-t $(IMAGE) \
		$(REPO_ROOT)

## kind-load: Load the image into every node of a kind cluster.
##             CLUSTER_NAME defaults to the first cluster returned by `kind get clusters`.
CLUSTER_NAME ?= $(shell kind get clusters 2>/dev/null | head -1)
kind-load: image
	kind load docker-image $(IMAGE) --name $(CLUSTER_NAME)

## clean: Remove build artefacts.
clean:
	rm -rf $(REPO_ROOT)/plugin/coredns-ovn-kubernetes/bin/
