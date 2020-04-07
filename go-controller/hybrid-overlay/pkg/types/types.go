package types

const (
	// HybridOverlayAnnotationBase holds the hybrid overlay annotation base
	HybridOverlayAnnotationBase = "k8s.ovn.org/hybrid-overlay-"
	// HybridOverlayNodeSubnet holds the pod CIDR assigned to the node
	HybridOverlayNodeSubnet = HybridOverlayAnnotationBase + "node-subnet"
	// HybridOverlayDRMAC holds the MAC address of the Distributed Router/gateway
	HybridOverlayDRMAC = HybridOverlayAnnotationBase + "distributed-router-gateway-mac"

	// HybridOverlayVNI is the VNI for VXLAN tunnels between nodes/endpoints
	HybridOverlayVNI = 4097
)
