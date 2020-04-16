package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"text/template"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/klog"

	cli "github.com/urfave/cli/v2"
	"gopkg.in/fsnotify/fsnotify.v1"

	hocontroller "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	ovnnode "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kexec "k8s.io/utils/exec"
)

const (
	// CustomAppHelpTemplate helps in grouping options to ovnkube
	CustomAppHelpTemplate = `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} [global options]

VERSION:
   {{.Version}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}

COMMANDS:{{range .VisibleCategories}}{{if .Name}}

   {{.Name}}:{{end}}{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}

GLOBAL OPTIONS:{{range $title, $category := getFlagsByCategory}}
   {{upper $title}}
   {{range $index, $option := $category}}{{if $index}}
   {{end}}{{$option}}{{end}}
   {{end}}`
)

func getFlagsByCategory() map[string][]cli.Flag {
	m := map[string][]cli.Flag{}
	m["Generic Options"] = config.CommonFlags
	m["CNI Options"] = config.CNIFlags
	m["K8s-related Options"] = config.K8sFlags
	m["OVN Northbound DB Options"] = config.OvnNBFlags
	m["OVN Southbound DB Options"] = config.OvnSBFlags
	m["OVN Gateway Options"] = config.OVNGatewayFlags
	m["Master HA Options"] = config.MasterHAFlags

	return m
}

// borrowed from cli packages' printHelpCustom()
func printOvnKubeHelp(out io.Writer, templ string, data interface{}, customFunc map[string]interface{}) {
	funcMap := template.FuncMap{
		"join":               strings.Join,
		"upper":              strings.ToUpper,
		"getFlagsByCategory": getFlagsByCategory,
	}
	for key, value := range customFunc {
		funcMap[key] = value
	}

	w := tabwriter.NewWriter(out, 1, 8, 2, ' ', 0)
	t := template.Must(template.New("help").Funcs(funcMap).Parse(templ))
	err := t.Execute(w, data)
	if err == nil {
		_ = w.Flush()
	}
}

func main() {
	cli.HelpPrinterCustom = printOvnKubeHelp
	c := cli.NewApp()
	c.Name = "ovnkube"
	c.Usage = "run ovnkube to start master, node, and gateway services"
	c.Version = config.Version
	c.CustomAppHelpTemplate = CustomAppHelpTemplate
	c.Flags = config.GetFlags(nil)

	c.Action = func(c *cli.Context) error {
		return runOvnKube(c)
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
		klog.Exit(err)
	}
}

func delPidfile(pidfile string) {
	if pidfile != "" {
		if _, err := os.Stat(pidfile); err == nil {
			if err := os.Remove(pidfile); err != nil {
				klog.Errorf("%s delete failed: %v", pidfile, err)
			}
		}
	}
}

func setupPIDFile(pidfile string) error {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		delPidfile(pidfile)
		os.Exit(1)
	}()

	// need to test if already there
	_, err := os.Stat(pidfile)

	// Create if it doesn't exist, else exit with error
	if os.IsNotExist(err) {
		if err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			klog.Errorf("failed to write pidfile %s (%v). Ignoring..", pidfile, err)
		}
	} else {
		// get the pid and see if it exists
		pid, err := ioutil.ReadFile(pidfile)
		if err != nil {
			return fmt.Errorf("pidfile %s exists but can't be read: %v", pidfile, err)
		}
		_, err1 := os.Stat("/proc/" + string(pid[:]) + "/cmdline")
		if os.IsNotExist(err1) {
			// Left over pid from dead process
			if err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
				klog.Errorf("failed to write pidfile %s (%v). Ignoring..", pidfile, err)
			}
		} else {
			return fmt.Errorf("pidfile %s exists and ovnkube is running", pidfile)
		}
	}

	return nil
}

func runOvnKube(ctx *cli.Context) error {
	pidfile := ctx.String("pidfile")
	if pidfile != "" {
		defer delPidfile(pidfile)
		if err := setupPIDFile(pidfile); err != nil {
			return err
		}
	}

	exec := kexec.New()
	configFile, err := config.InitConfig(ctx, exec, nil)
	if err != nil {
		return err
	}

	if err = util.SetExec(exec); err != nil {
		return fmt.Errorf("failed to initialize exec helper: %v", err)
	}

	clientset, err := util.NewClientset(&config.Kubernetes)
	if err != nil {
		return err
	}

	stopChan := make(chan struct{})

	master := ctx.String("init-master")
	node := ctx.String("init-node")

	cleanupNode := ctx.String("cleanup-node")
	if cleanupNode != "" {
		if master != "" || node != "" {
			return fmt.Errorf("cannot specify cleanup-node together with 'init-node or 'init-master'")
		}

		if err = ovnnode.CleanupClusterNode(cleanupNode); err != nil {
			return err
		}
		return nil
	}

	if master == "" && node == "" {
		return fmt.Errorf("need to run ovnkube in either master and/or node mode")
	}

	// Set up a watch on our config file; if it changes, we exit -
	// (we don't have the ability to dynamically reload config changes).
	if err := watchForChanges(configFile); err != nil {
		return fmt.Errorf("unable to setup configuration watch: %v", err)
	}

	f := informers.NewSharedInformerFactory(clientset, informer.DefaultResyncInterval)

	var ovnController *ovn.Controller
	if master != "" {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("Windows is not supported as master node")
		}
		// register prometheus metrics exported by the master
		metrics.RegisterMasterMetrics()
		ovnController = ovn.NewOvnController(
			clientset,
			f.Core().V1().Nodes().Informer(),
			f.Core().V1().Pods().Informer(),
			f.Core().V1().Services().Informer(),
			f.Core().V1().Endpoints().Informer(),
			f.Core().V1().Namespaces().Informer(),
			f.Networking().V1().NetworkPolicies().Informer(),
			stopChan,
		)
	}

	var nodeController *ovnnode.OvnNode
	if node != "" {
		if config.Kubernetes.Token == "" {
			return fmt.Errorf("cannot initialize node without service account 'token'. Please provide one with --k8s-token argument")
		}
		// register ovnkube node specific prometheus metrics exported by the node
		metrics.RegisterNodeMetrics()
		// register ovn specific (ovn-controller and ovn-northd) metrics
		metrics.RegisterOvnMetrics()
		nodeController = ovnnode.NewNode(
			clientset,
			node,
			f.Core().V1().Endpoints().Informer(),
			f.Core().V1().Services().Informer(),
		)
	}

	var hoController *hocontroller.HybridOverlayController
	if config.HybridOverlay.Enabled {
		var err error
		hoController, err = hocontroller.NewHybridOverlayController(
			master != "",
			node,
			clientset,
			f.Core().V1().Nodes().Informer(),
			f.Core().V1().Pods().Informer(),
		)
		if err != nil {
			return err
		}
	}

	// Start the informers
	f.Start(stopChan)

	if ovnController != nil {
		go ovnController.Start(clientset, master, stopChan)
	}

	if nodeController != nil {
		start := time.Now()
		go nodeController.Start(stopChan)
		// TODO: we should probably pass the metrics to the nodeController to return readiness
		// as start is async this metric is meaningless
		end := time.Since(start)
		metrics.MetricNodeReadyDuration.Set(end.Seconds())
	}

	if hoController != nil {
		go hoController.Run(stopChan)
	}

	// now that ovnkube master/node are running, lets expose the metrics HTTP endpoint if configured
	// start the prometheus server
	if config.Kubernetes.MetricsBindAddress != "" {
		metrics.StartMetricsServer(config.Kubernetes.MetricsBindAddress, config.Kubernetes.MetricsEnablePprof)
	}

	// run until cancelled
	select {
	case <-ctx.Context.Done():
		stopChan <- struct{}{}
	default:
		// noop
	}
	return nil
}

// watchForChanges exits if the configuration file changed.
func watchForChanges(configPath string) error {
	if configPath == "" {
		return nil
	}
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					klog.Infof("Configuration file %s changed, exiting...", event.Name)
					os.Exit(0)
					return
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				klog.Errorf("fsnotify error %v", err)
			}
		}
	}()

	// Watch all symlinks for changes
	p := configPath
	maxdepth := 100
	for depth := 0; depth < maxdepth; depth++ {
		if err := watcher.Add(p); err != nil {
			return err
		}
		klog.Infof("Watching config file %s for changes", p)

		stat, err := os.Lstat(p)
		if err != nil {
			return err
		}

		// configmaps are usually symlinks
		if stat.Mode()&os.ModeSymlink > 0 {
			p, err = filepath.EvalSymlinks(p)
			if err != nil {
				return err
			}
		} else {
			break
		}
	}

	return nil
}
