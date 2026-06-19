// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

// ARP inbound-suppression efficacy test.
//
// Background
// ----------
// Each primary UDN creates its own Gateway Router (GR) with a dedicated patch
// port in br-ex (breth0). Without suppression flows, any ARP broadcast that
// arrives on the physical uplink is replicated by OVS NORMAL to every patch
// port. Each UDN GR pipeline costs ~70 OVN resubmits; at 62 UDNs a single
// ARP drives ~4340 resubmits, exceeding the OVS 4096 limit.
//
// What this test checks
// ---------------------
//   1. Fan-out count — the priority-10 "dl_dst=<bridgeMAC>" flow in breth0
//      explicitly lists every patch port. We verify that after ARP suppression
//      flows are installed, an inbound ARP broadcast increments the suppression
//      flow counter and NOT the fan-out flow counter.
//
//   2. N/S connectivity — a pod in a primary UDN can ping the external gateway
//      under ARP broadcast load (arping from the docker-host bridge).
//
// Run:
//   cd test && make shard-test WHAT="ARP inbound suppression"

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
)

// numARPTestUDNs: 62 × ~70 resubmits ≈ 4340 > 4096 limit.
const numARPTestUDNs = 62

var _ = Describe("ARP inbound suppression with primary UDNs", func() {

	f := framework.NewDefaultFramework("arp-suppression")

	var (
		worker     string
		ovsPodName string
		nodeIP     string
		gwIP       string
		udnNSNames []string
		arpingCmd  *exec.Cmd
	)

	BeforeEach(func() {
		nodes, err := e2enode.GetReadySchedulableNodes(context.TODO(), f.ClientSet)
		Expect(err).NotTo(HaveOccurred())
		Expect(nodes.Items).NotTo(BeEmpty())
		// Prefer a non-control-plane node — the control-plane is near
		// the 110-pod limit from system components.
		workerNode := nodes.Items[0]
		for i := range nodes.Items {
			if _, isCP := nodes.Items[i].Labels["node-role.kubernetes.io/control-plane"]; !isCP {
				workerNode = nodes.Items[i]
				break
			}
		}
		worker = workerNode.Name
		nodeIP = nodeInternalIP(workerNode)
		gwIP = gwIPForNode(nodeIP)
		ovsPodName = ovsPodOnNode(f, worker)

		By(fmt.Sprintf("Creating %d primary UDNs on node %s", numARPTestUDNs, worker))
		udnNSNames = makeUDNsWithPods(f, worker, numARPTestUDNs)

		By("Waiting for UDN GR patch ports to appear in breth0")
		brName := deploymentconfig.Get().ExternalBridgeName()
		Eventually(func() int {
			return patchPortCount(f, ovsPodName, brName)
		}, 5*time.Minute, 10*time.Second).Should(
			BeNumerically(">=", numARPTestUDNs-3),
			"timed out waiting for UDN patch ports",
		)
	})

	AfterEach(func() {
		if arpingCmd != nil && arpingCmd.Process != nil {
			_ = arpingCmd.Process.Kill()
			arpingCmd = nil
		}
		for _, ns := range udnNSNames {
			_ = f.ClientSet.CoreV1().Namespaces().Delete(
				context.TODO(), ns, metav1.DeleteOptions{})
		}
		// Wait for pods to terminate so the next BeforeEach doesn't hit
		// the 110-pod-per-node limit with lingering Terminating pods.
		Eventually(func() int {
			pods, err := f.ClientSet.CoreV1().Pods(v1.NamespaceAll).List(
				context.TODO(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + worker})
			if err != nil {
				return 999
			}
			var nonSystem int
			for _, p := range pods.Items {
				if p.Namespace != "ovn-kubernetes" && p.Namespace != "kube-system" && p.Namespace != "local-path-storage" {
					nonSystem++
				}
			}
			return nonSystem
		}, 3*time.Minute, 5*time.Second).Should(BeZero(),
			"timed out waiting for test pods to terminate on %s", worker)
	})

	// ── Structural test ────────────────────────────────────────────────────

	It("ARP broadcasts hit the suppression flow, not the 62-port fan-out", func() {
		brName := deploymentconfig.Get().ExternalBridgeName()

		By("Counting ARP suppression flows (priority 15/16)")
		suppFlows := arpSuppressionFlowCount(f, ovsPodName, brName)
		Expect(suppFlows).To(BeNumerically(">=", 2),
			"expected ≥2 ARP suppression flows, found %d — is the patched build deployed?",
			suppFlows)

		By("Noting n_packets counters before injecting ARP")
		suppBefore := flowNPackets(f, ovsPodName, brName, `priority=15.*arp_op=1`)
		fanBefore := fanoutNPackets(f, ovsPodName, brName)

		By(fmt.Sprintf("Injecting 5 ARP broadcasts from host → node IP %s", nodeIP))
		injectARPs(nodeIP, 5)
		time.Sleep(2 * time.Second)

		suppAfter := flowNPackets(f, ovsPodName, brName, `priority=15.*arp_op=1`)
		fanAfter := fanoutNPackets(f, ovsPodName, brName)

		framework.Logf("Suppression flow Δ: +%d  Fan-out Δ: +%d",
			suppAfter-suppBefore, fanAfter-fanBefore)

		Expect(suppAfter-suppBefore).To(BeNumerically(">", 0),
			"suppression flow should have caught the ARP broadcasts")
		Expect(fanAfter-fanBefore).To(BeZero(),
			"fan-out flow must NOT be hit — ARP storm would exceed 4096 resubmit limit")
	})

	// ── Functional test ────────────────────────────────────────────────────

	It("N/S ping from UDN pod succeeds under inbound ARP broadcast load", func() {
		By(fmt.Sprintf("Starting background arping host → %s (simulates physical ARP load)", nodeIP))
		arpingCmd = startArping(nodeIP)
		time.Sleep(2 * time.Second)

		By(fmt.Sprintf("Pinging gateway %s from UDN pod via ovn-udn1", gwIP))
		var pass int
		for i := 0; i < 10; i++ {
			_, err := e2ekubectl.RunKubectl(udnNSNames[0],
				"exec", "test-pod", "--",
				"ping", "-I", "ovn-udn1", "-c", "1", "-W", "2", gwIP)
			if err == nil {
				pass++
			}
		}
		framework.Logf("N/S ping pass rate: %d/10", pass)
		Expect(pass).To(BeNumerically(">=", 8),
			"expected ≥8/10 pings; ARP storm may still be hitting UDN GR pipelines")
	})
})

// ── helpers ───────────────────────────────────────────────────────────────────

func makeUDNsWithPods(f *framework.Framework, node string, n int) []string {
	names := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ns := fmt.Sprintf("arp-udn-%s-%d", f.Namespace.Name, i)
		// Namespace must carry the label at creation time.
		_, err := f.ClientSet.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   ns,
				Labels: map[string]string{"k8s.ovn.org/primary-user-defined-network": ""},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		names = append(names, ns)

		manifest := fmt.Sprintf(`
apiVersion: k8s.ovn.org/v1
kind: UserDefinedNetwork
metadata:
  name: primary-udn
  namespace: %s
spec:
  topology: Layer3
  layer3:
    role: Primary
    subnets:
    - cidr: 10.200.%d.0/16
      hostSubnet: 24
`, ns, i)
		_, err = e2ekubectl.RunKubectlInput(ns, manifest, "apply", "-f", "-")
		Expect(err).NotTo(HaveOccurred())

		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: ns},
			Spec: v1.PodSpec{
				NodeName: node,
				Containers: []v1.Container{{
					Name:    "agnhost",
					Image:   images.AgnHost(),
					Command: []string{"/bin/sh", "-c", "sleep 3600"},
				}},
			},
		}
		_, err = f.ClientSet.CoreV1().Pods(ns).Create(context.TODO(), pod, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
	for _, ns := range names {
		err := e2epod.WaitTimeoutForPodRunningInNamespace(
			context.Background(), f.ClientSet, "test-pod", ns, 2*time.Minute)
		Expect(err).NotTo(HaveOccurred(), "pod in %s not Running", ns)
	}
	return names
}

func patchPortCount(f *framework.Framework, ovsPod, br string) int {
	out, _ := e2ekubectl.RunKubectl("ovn-kubernetes", "exec", ovsPod, "--",
		"ovs-vsctl", "list-ports", br)
	count := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "patch") {
			count++
		}
	}
	return count
}

func arpSuppressionFlowCount(f *framework.Framework, ovsPod, br string) int {
	out, _ := e2ekubectl.RunKubectl("ovn-kubernetes", "exec", ovsPod, "--",
		"ovs-ofctl", "dump-flows", br)
	return len(regexp.MustCompile(`priority=1[56].*arp_op=1`).FindAllString(out, -1))
}

func flowNPackets(f *framework.Framework, ovsPod, br, pattern string) int {
	out, _ := e2ekubectl.RunKubectl("ovn-kubernetes", "exec", ovsPod, "--",
		"ovs-ofctl", "dump-flows", br)
	re := regexp.MustCompile(pattern)
	np := regexp.MustCompile(`n_packets=(\d+)`)
	for _, line := range strings.Split(out, "\n") {
		if re.MatchString(line) {
			if m := np.FindStringSubmatch(line); m != nil {
				v, _ := strconv.Atoi(m[1])
				return v
			}
		}
	}
	return 0
}

func fanoutNPackets(f *framework.Framework, ovsPod, br string) int {
	out, _ := e2ekubectl.RunKubectl("ovn-kubernetes", "exec", ovsPod, "--",
		"ovs-ofctl", "dump-flows", br)
	np := regexp.MustCompile(`n_packets=(\d+)`)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "priority=10") && strings.Contains(line, "dl_dst=") {
			if m := np.FindStringSubmatch(line); m != nil {
				v, _ := strconv.Atoi(m[1])
				return v
			}
		}
	}
	return 0
}

func kindBridge() string {
	out, err := exec.Command("docker", "network", "ls",
		"--filter", "name=kind", "-q").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return ""
	}
	id := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	return "br-" + id
}

func injectARPs(targetIP string, n int) {
	br := kindBridge()
	if br == "" {
		framework.Logf("WARNING: kind bridge not found, skipping arping injection")
		return
	}
	for i := 0; i < n; i++ {
		_ = exec.Command("arping", "-c", "1", "-I", br, targetIP).Run()
	}
}

func startArping(targetIP string) *exec.Cmd {
	br := kindBridge()
	if br == "" {
		framework.Logf("WARNING: kind bridge not found, no background arping")
		return nil
	}
	cmd := exec.Command("arping", "-I", br, "-c", "9999", targetIP)
	if err := cmd.Start(); err != nil {
		framework.Logf("WARNING: arping failed to start: %v", err)
		return nil
	}
	framework.Logf("Background arping: arping -I %s -c 9999 %s (pid %d)",
		br, targetIP, cmd.Process.Pid)
	return cmd
}

func nodeInternalIP(node v1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type == v1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}

func gwIPForNode(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	parts[3] = "1"
	return strings.Join(parts, ".")
}

func ovsPodOnNode(f *framework.Framework, node string) string {
	pods, err := f.ClientSet.CoreV1().Pods("ovn-kubernetes").List(context.TODO(),
		metav1.ListOptions{
			LabelSelector: "app=ovs-node",
			FieldSelector: "spec.nodeName=" + node,
		})
	Expect(err).NotTo(HaveOccurred())
	Expect(pods.Items).NotTo(BeEmpty())
	return pods.Items[0].Name
}
