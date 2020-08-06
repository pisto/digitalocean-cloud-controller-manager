/*
Copyright 2020 DigitalOcean

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package do

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

const (
	// Interval of synchronizing service status from apiserver.
	serviceSyncPeriod = 35 * time.Second
	// Frequency at which the firewall controller runs.
	firewallReconcileFrequency = 5 * time.Minute
)

var (
	// Outbound rules that we commonly use for our internal firewalls, it is what we should
	// use for public access firewalls too.
	allowAllOutboundRules = []godo.OutboundRule{
		{
			Protocol:  "tcp",
			PortRange: "all",
			Destinations: &godo.Destinations{
				Addresses: []string{"0.0.0.0/0", "::/0"},
			},
		},
		{
			Protocol:  "udp",
			PortRange: "all",
			Destinations: &godo.Destinations{
				Addresses: []string{"0.0.0.0/0", "::/0"},
			},
		},
		{
			Protocol: "icmp",
			Destinations: &godo.Destinations{
				Addresses: []string{"0.0.0.0/0", "::/0"},
			},
		},
	}
)

// firewallCache stores a cached firewall and mutex to handle concurrent access.
type firewallCache struct {
	mu       *sync.RWMutex // protects firewall.
	firewall *godo.Firewall
}

// firewallManagerOp manages the interaction with the DO Firewalls API.
type firewallManagerOp struct {
	client             *godo.Client
	fwCache            firewallCache
	workerFirewallName string
	workerFirewallTags []string
}

// FirewallManager retrieves and stores firewall representations.
type FirewallManager interface {
	// Get returns the current public access firewall representation (i.e., the DO Firewall object)
	// if it exists and nil if it does not exist.
	Get(ctx context.Context) (*godo.Firewall, error)

	// Set applies the given inbound rules to the public access firewall.
	Set(ctx context.Context, inboundRules []godo.InboundRule) error
}

// FirewallController helps to keep cloud provider service firewalls in sync.
type FirewallController struct {
	kubeClient         clientset.Interface
	client             *godo.Client
	workerFirewallTags []string
	serviceLister      corelisters.ServiceLister
	fwManager          FirewallManager
}

// NewFirewallController returns a new firewall controller to reconcile public access firewall state.
func NewFirewallController(
	ctx context.Context,
	kubeClient clientset.Interface,
	client *godo.Client,
	serviceInformer coreinformers.ServiceInformer,
	fwManager FirewallManager,
	workerFirewallTags []string,
) *FirewallController {
	fc := &FirewallController{
		kubeClient:         kubeClient,
		client:             client,
		workerFirewallTags: workerFirewallTags,
		fwManager:          fwManager,
	}

	serviceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				err := fc.ensureReconciledFirewall(ctx)
				if err != nil {
					klog.Errorf("failed to reconcile worker firewall: %s", err)
				}
			},
			UpdateFunc: func(old, cur interface{}) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				err := fc.ensureReconciledFirewall(ctx)
				if err != nil {
					klog.Errorf("failed to reconcile worker firewall: %s", err)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				err := fc.ensureReconciledFirewall(ctx)
				if err != nil {
					klog.Errorf("failed to reconcile worker firewall: %s", err)
				}
			},
		},
		serviceSyncPeriod,
	)
	fc.serviceLister = serviceInformer.Lister()

	return fc
}

// Run starts the firewall controller loop.
func (fc *FirewallController) Run(stopCh <-chan struct{}, fm *firewallManagerOp, fwReconcileFrequency time.Duration) {
	wait.Until(func() {
		ctx, cancel := context.WithTimeout(context.Background(), fwReconcileFrequency)
		defer cancel()

		currentFirewall, err := fc.fwManager.Get(ctx)
		if err != nil {
			klog.Errorf("failed to get worker firewall: %s", err)
		}

		if currentFirewall != nil {
			if fm.fwCache.isEqual(currentFirewall) {
				return
			}
		}
		fm.fwCache.updateCache(currentFirewall)
		err = fc.ensureReconciledFirewall(ctx)
		if err != nil {
			klog.Errorf("failed to reconcile worker firewall: %s", err)
		}
		klog.Info("successfully reconciled firewall")

	}, fwReconcileFrequency, stopCh)
}

// Get returns the current public access firewall representation.
func (fm *firewallManagerOp) Get(ctx context.Context) (*godo.Firewall, error) {
	// check cache and query the API firewall service to get firewall ID, if it exists. Return it. If not, continue.
	fw := fm.fwCache.getCachedFirewall()
	if fw != nil {
		fw, resp, err := fm.client.Firewalls.Get(ctx, fw.ID)
		if err != nil && (resp == nil || resp.StatusCode != http.StatusNotFound) {
			return nil, fmt.Errorf("could not get firewall: %v", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			klog.Warningf("unable to retrieve firewall by ID because it no longer exists")
		}
		if fw != nil {
			return fw, nil
		}
	}

	// iterate through firewall API provided list and return the firewall with the matching firewall name.
	f := func(fw godo.Firewall) bool {
		return fw.Name == fm.workerFirewallName
	}
	klog.Info("filtering firewall list for the firewall that has the expected firewall name")
	fw, err := filterFirewallList(ctx, fm.client, f)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve list of firewalls from DO API: %v", err)
	}
	return fw, nil
}

// Set applies the given inbound rules to the public access firewall when the current rules and target rules differ.
func (fm *firewallManagerOp) Set(ctx context.Context, svcInboundRules []godo.InboundRule) error {
	targetFirewall := fm.fwCache.getCachedFirewall()
	isEqual := false
	// A locally cached firewall with matching rules means there is nothing to update.
	if targetFirewall != nil {
		if cmp.Equal(targetFirewall.InboundRules, svcInboundRules) {
			isEqual = true
		}
		if !cmp.Equal(targetFirewall.OutboundRules, allowAllOutboundRules) {
			klog.Info("reconciling outbound rules")
			// reconcile away any changes to the inbound or outbound rules and update firewall API
			fm.reconcileOutboundRules(ctx, targetFirewall)
		}
	}

	if isEqual {
		return nil
	}

	// A locally cached firewall exists, but the inbound rules don't match the expected
	// service inbound rules. So we need to use the locally cached firewall ID to attempt
	// to update the firewall APIs representation of the firewall with the new rules.
	//
	// Then we update the local cache with the firewall returned from the Update request.
	if targetFirewall != nil {
		klog.Info("reconciling inbound rules")
		if svcInboundRules == nil {
			// clear out inbound rules in the local cache
			fm.fwCache.clearInboundRules(targetFirewall)
			return nil
		}
		fr := fm.createFirewallRequest(svcInboundRules)
		currentFirewall, resp, err := fm.client.Firewalls.Update(ctx, targetFirewall.ID, fr)
		if err != nil {
			if resp == nil || resp.StatusCode != http.StatusNotFound {
				return fmt.Errorf("could not update firewall: %v", err)
			}
			// Firewall does not exist, so we need to create a new firewall with the
			// updated inbound rules.
			currentFirewall, err = fm.createFirewall(ctx, svcInboundRules)
			if err != nil {
				return fmt.Errorf("could not create firewall: %v", err)
			}
			klog.Info("successfully created firewall")
		}
		fm.fwCache.updateCache(currentFirewall)
		return nil
	}

	// Check if the target firewall ID exists but in the case that CCM first starts up and the
	// firewall ID does not exist yet, we have to retrieve one from the API.
	if targetFirewall == nil {
		currentFirewall, err := fm.Get(ctx)
		if err != nil {
			return err
		}
		if currentFirewall == nil {
			klog.Info("an existing firewall not found, we need to create one")
			currentFirewall, err = fm.createFirewall(ctx, svcInboundRules)
			if err != nil {
				return err
			}
			klog.Info("successfully created firewall")
		}
		fm.fwCache.updateCache(currentFirewall)
	}
	return nil
}

func (fm *firewallManagerOp) createFirewall(ctx context.Context, svcInboundRules []godo.InboundRule) (*godo.Firewall, error) {
	fr := fm.createFirewallRequest(svcInboundRules)
	currentFirewall, _, err := fm.client.Firewalls.Create(ctx, fr)
	return currentFirewall, err
}

func (fm *firewallManagerOp) createFirewallRequest(inboundRules []godo.InboundRule) *godo.FirewallRequest {
	return &godo.FirewallRequest{
		Name:          fm.workerFirewallName,
		InboundRules:  inboundRules,
		OutboundRules: allowAllOutboundRules,
		Tags:          fm.workerFirewallTags,
	}
}

func (fm *firewallManagerOp) reconcileOutboundRules(ctx context.Context, targetFirewall *godo.Firewall) error {
	rules := &godo.FirewallRulesRequest{
		// purposely exclude InboundRules in order to remove them
		OutboundRules: allowAllOutboundRules,
	}
	resp, err := fm.client.Firewalls.AddRules(ctx, targetFirewall.ID, rules)
	if err != nil {
		if resp == nil || resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("could not update firewall: %v", err)
		}
	}
	return nil
}

func (fc *FirewallController) ensureReconciledFirewall(ctx context.Context) error {
	serviceList, err := fc.serviceLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}
	inboundRules := fc.createInboundRules(serviceList)
	err = fc.fwManager.Set(ctx, inboundRules)
	if err != nil {
		return err
	}
	return nil
}

func (fc *FirewallController) createInboundRules(serviceList []*v1.Service) []godo.InboundRule {
	var nodePortInboundRules []godo.InboundRule
	for _, svc := range serviceList {
		if svc.Spec.Type == v1.ServiceTypeNodePort {
			// this is a nodeport service so we should check for existing inbound rules on all ports.
			for _, servicePort := range svc.Spec.Ports {
				// In the odd case that a failure is asynchronous causing the NodePort to be set to zero.
				if servicePort.NodePort == 0 {
					klog.Warningf("NodePort on the service is set to zero")
					continue
				}
				nodePortInboundRules = append(nodePortInboundRules,
					godo.InboundRule{
						Protocol:  "tcp",
						PortRange: strconv.Itoa(int(servicePort.NodePort)),
						Sources: &godo.Sources{
							Tags: fc.workerFirewallTags,
						},
					},
					godo.InboundRule{
						Protocol:  "udp",
						PortRange: strconv.Itoa(int(servicePort.NodePort)),
						Sources: &godo.Sources{
							Tags: fc.workerFirewallTags,
						},
					},
				)
			}
		}
	}
	return nodePortInboundRules
}

func (fc *firewallCache) clearInboundRules(fw *godo.Firewall) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.firewall = &godo.Firewall{
		ID:            fw.ID,
		Name:          fw.Name,
		Status:        fw.Status,
		OutboundRules: allowAllOutboundRules,
		DropletIDs:    fw.DropletIDs,
		Tags:          fw.Tags,
	}
}

func (fc *firewallCache) getCachedFirewall() *godo.Firewall {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	fw := fc.firewall
	return fw
}

func (fc *firewallCache) isEqual(fw *godo.Firewall) bool {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return cmp.Equal(fc.firewall, fw)
}

func (fc *firewallCache) updateCache(currentFirewall *godo.Firewall) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.firewall = currentFirewall
}
