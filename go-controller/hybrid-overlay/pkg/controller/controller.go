package controller

import (
	"k8s.io/client-go/kubernetes"
)

// StartHybridOverlay starts one or both of the master and node controllers for
// hybrid overlay
func StartHybridOverlay(master bool, nodeName string, clientset kubernetes.Interface, stopChan <-chan struct{}) error {
	if master {
		masterController, err := NewMaster(clientset, stopChan)
		if err != nil {
			return err
		}
		// TODO: Add factory back
		if err := masterController.Start(); err != nil {
			return err
		}
	}

	if nodeName != "" {
		nodeController, err := NewNode(clientset, nodeName, stopChan)
		if err != nil {
			return err
		}
		// TODO: Add factory back
		if err := nodeController.Start(); err != nil {
			return err
		}
	}

	return nil
}
