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
	"errors"
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
	serviceSyncPeriod = 30 * time.Second
	// Frequency at which the firewall controller runs.
	firewallReconcileFrequency = 5 * time.Minute
)

var (
	// Sentinel errors make it easier to test.
	errFailedToAddInboundRules        = errors.New("failed to add new firewall inbound rules")
	errFailedToCreateFirewallOnUpdate = errors.New("failed to create firewall after found missing on update")
	errFailedToListServices           = errors.New("failed to list services")
	errFailedToRetrieveFirewallByID   = errors.New("failed to retrieve firewall by ID")
	errFailedToRetrieveFirewallList   = errors.New("failed to retrieve list of firewalls from DO API")
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
				fc.ensureReconciledFirewall(ctx)
			},
			UpdateFunc: func(old, cur interface{}) {
				fc.ensureReconciledFirewall(ctx)
			},
			DeleteFunc: func(obj interface{}) {
				fc.ensureReconciledFirewall(ctx)
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
			fm.fwCache.mu.RLock()
			isEqual := cmp.Equal(currentFirewall, fm.fwCache.firewall)
			fm.fwCache.mu.RUnlock()

			if isEqual {
				return
			}
		}
		err = fc.ensureReconciledFirewall(ctx)
		if err != nil {
			klog.Errorf("failed to reconcile worker firewall: %s", err)
		}

	}, fwReconcileFrequency, stopCh)
}

// Get returns the current public access firewall representation.
func (fm *firewallManagerOp) Get(ctx context.Context) (*godo.Firewall, error) {
	// check cache and query the API firewall service to get firewall ID, if it exists. Return it. If not, continue.
	var fw *godo.Firewall
	fm.fwCache.mu.RLock()
	fw = fm.fwCache.firewall
	fm.fwCache.mu.RUnlock()

	if fw != nil {
		fm.fwCache.mu.RLock()
		fwID := fm.fwCache.firewall.ID
		fm.fwCache.mu.RUnlock()

		fw, resp, err := fm.client.Firewalls.Get(ctx, fwID)
		if err != nil && (resp == nil || resp.StatusCode != http.StatusNotFound) {
			return nil, errFailedToRetrieveFirewallByID
		}
		if resp.StatusCode == http.StatusNotFound {
			klog.Warningf("unable to retrieve firewall by ID because it no longer exists")
		}
		if fw != nil {
			// Update the local cache here in case a consumer, other than Set(), calls this function.
			// This will ensure that we have an up-to-date cache.
			fm.fwCache.updateCache(fw)
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
		return nil, errFailedToRetrieveFirewallList
	}
	return fw, nil
}

// Set applies the given inbound rules to the public access firewall when the current rules and target rules differ.
func (fm *firewallManagerOp) Set(ctx context.Context, svcInboundRules []godo.InboundRule) error {
	fm.fwCache.mu.RLock()
	targetFirewall := fm.fwCache.firewall
	isEqual := false
	// A locally cached firewall with matching rules means there is nothing to update.
	if targetFirewall != nil && cmp.Equal(targetFirewall.InboundRules, svcInboundRules) {
		isEqual = true
	}
	fm.fwCache.mu.RUnlock()

	if isEqual {
		return nil
	}

	var fwID string

	// A locally cached firewall exists, but the inbound rules don't match the expected
	// service inbound rules. So we need to use the locally cached firewall ID to attempt
	// to update the firewall APIs representation of the firewall with the new rules.
	//
	// Then we update the local cache with the firewall returned from the Update request.
	if targetFirewall != nil {
		fm.fwCache.mu.RLock()
		fwID = targetFirewall.ID
		fm.fwCache.mu.RUnlock()

		fr := fm.createFirewallRequest(fm.workerFirewallName, fm.workerFirewallTags, svcInboundRules)
		currentFirewall, resp, err := fm.client.Firewalls.Update(ctx, fwID, fr)
		if err != nil {
			if resp == nil || resp.StatusCode != http.StatusNotFound {
				return errFailedToAddInboundRules
			}
			// Firewall does not exist, so we need to create a new firewall with the
			// updated inbound rules.
			currentFirewall, err = fm.createFirewall(ctx, svcInboundRules)
			if err != nil {
				return errFailedToCreateFirewallOnUpdate
			}
			klog.Infof("successfully created firewall")
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
			klog.Infof("an existing firewall not found, we need to create one")
			currentFirewall, err = fm.createFirewall(ctx, svcInboundRules)
			if err != nil {
				return err
			}
			klog.Infof("successfully created firewall")
		}
		fm.fwCache.updateCache(currentFirewall)
	}
	return nil
}

func (fm *firewallManagerOp) createFirewall(ctx context.Context, svcInboundRules []godo.InboundRule) (*godo.Firewall, error) {
	fr := fm.createFirewallRequest(fm.workerFirewallName, fm.workerFirewallTags, svcInboundRules)
	currentFirewall, _, err := fm.client.Firewalls.Create(ctx, fr)
	return currentFirewall, err
}

func (fm *firewallManagerOp) createFirewallRequest(fwName string, fwTags []string, rules []godo.InboundRule) *godo.FirewallRequest {
	return &godo.FirewallRequest{
		Name:         fwName,
		InboundRules: rules,
		Tags:         fwTags,
	}
}

func (fc *firewallCache) updateCache(currentFirewall *godo.Firewall) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.firewall = currentFirewall
}

func (fc *FirewallController) ensureReconciledFirewall(ctx context.Context) error {
	serviceList, err := fc.serviceLister.List(labels.Everything())
	if err != nil {
		return errFailedToListServices
	}
	inboundRules := fc.createInboundRules(serviceList)
	fc.fwManager.Set(ctx, inboundRules)
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
					godo.InboundRule{
						Protocol:  "icmp",
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
