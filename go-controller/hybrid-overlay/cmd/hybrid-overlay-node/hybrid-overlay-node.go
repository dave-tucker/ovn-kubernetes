package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	cli "github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/client-go/informers"
	"k8s.io/klog"
	kexec "k8s.io/utils/exec"
)

var nodeName string

func main() {
	c := cli.NewApp()
	c.Name = "hybrid-overlay-node"
	c.Usage = "a node controller to integrate disparate networks with VXLAN tunnels"
	c.Version = config.Version
	c.Flags = config.GetFlags([]cli.Flag{
		&cli.StringFlag{
			Name:        "node",
			Usage:       "The name of this node in the Kubernetes cluster.",
			Destination: &nodeName,
		}})
	c.Action = func(c *cli.Context) error {
		if err := runHybridOverlay(c); err != nil {
			panic(err.Error())
		}
		return nil
	}

	ctx := context.Background()

	// trap Ctrl+C and call cancel on the context
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	defer func() {
		signal.Stop(ch)
		cancel()
	}()
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := c.RunContext(ctx, os.Args); err != nil {
		klog.Fatal(err)
	}
}

func runHybridOverlay(ctx *cli.Context) error {
	exec := kexec.New()
	if _, err := config.InitConfig(ctx, exec, nil); err != nil {
		return err
	}

	if err := util.SetExecWithoutOVS(exec); err != nil {
		return err
	}

	if nodeName == "" {
		return fmt.Errorf("missing node name; use the 'node' flag to provide one")
	}

	clientset, err := util.NewClientset(&config.Kubernetes)
	if err != nil {
		return err
	}

	stopChan := make(chan struct{})
	defer close(stopChan)

	f := informers.NewSharedInformerFactory(clientset, informer.DefaultResyncInterval)
	controller, err := controller.NewHybridOverlayController(
		false,
		nodeName,
		clientset,
		f.Core().V1().Nodes().Informer(),
		f.Core().V1().Pods().Informer(),
	)
	if err != nil {
		return err
	}

	f.Start(stopChan)
	go controller.Run(stopChan)

	// run until cancelled
	select {
	case <-ctx.Context.Done():
		stopChan <- struct{}{}
	default:
		// noop
	}
	return nil
}
