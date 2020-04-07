package controller

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"

	kapi "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// HybridOverlayEventHandler handles both Node and Pod events for the controller
type HybridOverlayEventHandler interface {
	AddNode(node *kapi.Node) error
	DeleteNode(node *kapi.Node) error
	AddPod(pod *kapi.Pod) error
	DeletePod(pod *kapi.Pod) error
}

// HybridOverlayController encapsulates client/master event handlers and state required to implement the controller pattern
type HybridOverlayController struct {
	HybridOverlayEventHandler
	nodeInformer informer.EventHandler
	podInformer  informer.EventHandler
}

// NewHybridOverlayController creates a new controller
func NewHybridOverlayController(
	master bool,
	nodeName string,
	clientset kubernetes.Interface,
	nodeInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
) (*HybridOverlayController, error) {
	var handler HybridOverlayEventHandler
	var err error
	if master {
		handler, err = NewMaster(clientset)
	} else {
		handler, err = NewNode(clientset, nodeName)
	}
	if err != nil {
		return nil, err
	}
	c := &HybridOverlayController{
		HybridOverlayEventHandler: handler,
	}

	c.nodeInformer = informer.NewDefaultEventHandler("node", nodeInformer,
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return c.HybridOverlayEventHandler.AddNode(node)
		},
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return c.HybridOverlayEventHandler.DeleteNode(node)
		},
	)
	c.podInformer = informer.NewDefaultEventHandler("pod", podInformer,
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			return c.HybridOverlayEventHandler.AddPod(pod)
		},
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			return c.HybridOverlayEventHandler.DeletePod(pod)
		},
	)
	return c, nil
}

// Run starts the controller. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *HybridOverlayController) Run(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting Hybrid Overlay Controller")

	klog.Info("Starting workers")
	go c.nodeInformer.Run(informer.DefaultNodeInformerThreadiness, stopCh)
	go c.podInformer.Run(informer.DefaultInformerThreadiness, stopCh)

	klog.Info("Started workers")
	<-stopCh
	klog.Info("Shutting down workers")
	return nil
}
