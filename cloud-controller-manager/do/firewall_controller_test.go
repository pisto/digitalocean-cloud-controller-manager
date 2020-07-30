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
	"sync"
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

var (
	ctx = context.TODO()

	kclient kubernetes.Interface

	inf = informers.NewSharedInformerFactory(kclient, 0)

	fakeWorkerFWName = "firewall"
	fakeWorkerFWTags = []string{"tag1", "tag2"}

	fakeInboundRule = godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31000",
		Sources: &godo.Sources{
			Tags:       []string{"tag"},
			DropletIDs: []int{1},
		},
	}

	diffFakeInboundRule = godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "32000",
		Sources: &godo.Sources{
			Tags:       []string{"tag"},
			DropletIDs: []int{1, 2},
		},
	}

	fwManagerOp FirewallManager
)

// fakeFirewallService satisfies the FirewallsService interface.
type fakeFirewallService struct {
	getFunc            func(context.Context, string) (*godo.Firewall, *godo.Response, error)
	createFunc         func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
	updateFunc         func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
	deleteFunc         func(context.Context, string) (*godo.Response, error)
	listFunc           func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
	listByDropletFunc  func(context.Context, int, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
	addDropletsFunc    func(context.Context, string, ...int) (*godo.Response, error)
	removeDropletsFunc func(context.Context, string, ...int) (*godo.Response, error)
	addTagsFunc        func(context.Context, string, ...string) (*godo.Response, error)
	removeTagsFunc     func(context.Context, string, ...string) (*godo.Response, error)
	addRulesFunc       func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
	removeRulesFunc    func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
}

// Get an existing Firewall by its identifier.
func (f *fakeFirewallService) Get(ctx context.Context, fID string) (*godo.Firewall, *godo.Response, error) {
	return f.getFunc(ctx, fID)
}

// Create a new Firewall with a given configuration.
func (f *fakeFirewallService) Create(ctx context.Context, fr *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
	return f.createFunc(ctx, fr)
}

// Update an existing Firewall with new configuration.
func (f *fakeFirewallService) Update(ctx context.Context, fID string, fr *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
	return f.updateFunc(ctx, fID, fr)
}

// Delete a Firewall by its identifier.
func (f *fakeFirewallService) Delete(ctx context.Context, fID string) (*godo.Response, error) {
	return f.deleteFunc(ctx, fID)
}

// List Firewalls.
func (f *fakeFirewallService) List(ctx context.Context, opt *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
	return f.listFunc(ctx, opt)
}

// ListByDroplet Firewalls.
func (f *fakeFirewallService) ListByDroplet(ctx context.Context, dID int, opt *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
	return f.listByDropletFunc(ctx, dID, opt)
}

// AddDroplets to a Firewall.
func (f *fakeFirewallService) AddDroplets(ctx context.Context, fID string, dropletIDs ...int) (*godo.Response, error) {
	return f.addDropletsFunc(ctx, fID)
}

// RemoveDroplets from a Firewall.
func (f *fakeFirewallService) RemoveDroplets(ctx context.Context, fID string, dropletIDs ...int) (*godo.Response, error) {
	return f.removeDropletsFunc(ctx, fID, dropletIDs...)
}

// AddTags to a Firewall.
func (f *fakeFirewallService) AddTags(ctx context.Context, fID string, tags ...string) (*godo.Response, error) {
	return f.addTagsFunc(ctx, fID, tags...)
}

// RemoveTags from a Firewall.
func (f *fakeFirewallService) RemoveTags(ctx context.Context, fID string, tags ...string) (*godo.Response, error) {
	return f.removeTagsFunc(ctx, fID, tags...)
}

// AddRules to a Firewall.
func (f *fakeFirewallService) AddRules(ctx context.Context, fID string, rr *godo.FirewallRulesRequest) (*godo.Response, error) {
	return f.addRulesFunc(ctx, fID, rr)
}

// RemoveRules from a Firewall.
func (f *fakeFirewallService) RemoveRules(ctx context.Context, fID string, rr *godo.FirewallRulesRequest) (*godo.Response, error) {
	return f.removeRulesFunc(ctx, fID, rr)
}

func newFakeFirewall(workerFirewallName string, inboundRule godo.InboundRule) *godo.Firewall {
	return &godo.Firewall{
		ID:           "123",
		Name:         workerFirewallName,
		InboundRules: []godo.InboundRule{inboundRule},
	}
}

func newFakeFirewallManagerOp(client *godo.Client, cache firewallCache) *firewallManagerOp {
	return &firewallManagerOp{
		client:             client,
		fwCache:            cache,
		workerFirewallName: fakeWorkerFWName,
		workerFirewallTags: fakeWorkerFWTags,
	}
}

func newFakeFirewallCache(inboundRules []godo.InboundRule) firewallCache {
	return firewallCache{
		mu: new(sync.RWMutex),
		firewall: &godo.Firewall{
			ID:           "123",
			Name:         fakeWorkerFWName,
			InboundRules: inboundRules,
		},
	}
}

func newFakeFirewallCacheEmpty() firewallCache {
	return firewallCache{
		mu: new(sync.RWMutex),
	}
}

func newFakeGodoClient(fakeFirewall *fakeFirewallService) *godo.Client {
	return &godo.Client{
		Firewalls: fakeFirewall,
	}
}

func TestFirewallController_Get(t *testing.T) {
	testcases := []struct {
		name                         string
		fwCache                      firewallCache
		expectedGodoFirewallGetResp  func(context.Context, string) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallListResp func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
		expectedError                error
		expectedFirewall             *godo.Firewall
	}{
		{
			name:    "return error when error on GET firewall by ID",
			fwCache: newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errFailedToRetrieveFirewallByID
			},
			expectedError: errFailedToRetrieveFirewallByID,
		},
		{
			name:    "return error when error on List firewalls",
			fwCache: newFakeFirewallCacheEmpty(),
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errFailedToRetrieveFirewallList
			},
			expectedError: errFailedToRetrieveFirewallList,
		},
		{
			name:    "nothing to return when there is no ID or firewall name match in firewall list",
			fwCache: newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
		},
		{
			name:    "handle 404 response code from GET firewall by ID and instead return firewall from List",
			fwCache: newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), errors.New("got an error")
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(fakeWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedFirewall: newFakeFirewall(fakeWorkerFWName, fakeInboundRule),
		},
		{
			name:    "get firewall from API with cached firewall ID",
			fwCache: newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			expectedFirewall: newFakeFirewall(fakeWorkerFWName, fakeInboundRule),
		},
		{
			name:    "when cache does not exist",
			fwCache: newFakeFirewallCacheEmpty(),
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
		},
	}
	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					getFunc:  test.expectedGodoFirewallGetResp,
					listFunc: test.expectedGodoFirewallListResp,
				},
			)
			fwManagerOp = newFakeFirewallManagerOp(gclient, test.fwCache)

			fw, err := fwManagerOp.Get(ctx)
			if want, got := test.expectedError, err; want != got {
				t.Errorf("incorrect firewall config\nwant: %#v\n got: %#v", want, got)
			}

			if diff := cmp.Diff(test.expectedFirewall, fw); diff != "" {
				t.Errorf("Get() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFirewallController_Set(t *testing.T) {
	testcases := []struct {
		name                           string
		fwCache                        firewallCache
		inboundRules                   []godo.InboundRule
		expectedGodoFirewallCreateResp func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallGetResp    func(context.Context, string) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallListResp   func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
		expectedGodoFirewallUpdateResp func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedError                  error
		expectedFirewall               *godo.Firewall
	}{
		{
			name:         "create firewall when cache does not exist (i.e. initial startup)",
			fwCache:      newFakeFirewallCacheEmpty(),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{}, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
		},
		{
			name:         "failing to update the firewall because of an unexpected error",
			fwCache:      newFakeFirewallCache([]godo.InboundRule{diffFakeInboundRule}),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), errors.New("unexpected error")
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(fakeWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errors.New("unexpected error")
			},
			expectedError: errFailedToCreateFirewallOnUpdate,
		},
		{
			name:         "return error when failing to add inbound rules on update request to firewall API",
			fwCache:      newFakeFirewallCache([]godo.InboundRule{diffFakeInboundRule}),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errFailedToAddInboundRules
			},
			expectedError: errFailedToAddInboundRules,
		},
		{
			name:         "when the firewall cache is nil return existing firewall from API then update cache",
			fwCache:      newFakeFirewallCacheEmpty(),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(fakeWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					listFunc:   test.expectedGodoFirewallListResp,
					updateFunc: test.expectedGodoFirewallUpdateResp,
					createFunc: test.expectedGodoFirewallCreateResp,
					getFunc:    test.expectedGodoFirewallGetResp,
				},
			)
			fwManagerOp = newFakeFirewallManagerOp(gclient, test.fwCache)
			fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, []string{})

			err := fc.fwManager.Set(ctx, test.inboundRules)
			if want, got := test.expectedError, err; want != got {
				t.Errorf("incorrect firewall config\nwant: %#v\n got: %#v", want, got)
			}
		})
	}
}

func TestFirewallController_createInboundRules(t *testing.T) {
	inboundRules := []godo.InboundRule{
		{
			Protocol:  "tcp",
			PortRange: "31220",
			Sources: &godo.Sources{
				Tags: []string{"tag"},
			},
		},
		{
			Protocol:  "tcp",
			PortRange: "20000",
			Sources: &godo.Sources{
				Tags: []string{"tag"},
			},
		},
		{
			Protocol:  "tcp",
			PortRange: "40000",
			Sources: &godo.Sources{
				Tags: []string{"tag"},
			},
		},
		{
			Protocol:  "tcp",
			PortRange: "30000",
			Sources: &godo.Sources{
				Tags: []string{"tag"},
			},
		},
		{
			Protocol:  "tcp",
			PortRange: "32727",
			Sources: &godo.Sources{
				Tags: []string{"tag"},
			},
		},
	}
	testNodePortService1 := &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: "tcp",
					Port:     31220,
					NodePort: 31220,
				},
			},
		},
	}
	testNodePortService2 := &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: "tcp",
					Port:     30000,
					NodePort: 30000,
				},
			},
		},
	}
	testNodePortService3 := &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: "tcp",
					Port:     32727,
					NodePort: 32727,
				},
			},
		},
	}
	testLBService := &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Protocol: "tcp",
					Port:     20000,
				},
			},
		},
	}
	testService := &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{
					Protocol: "tcp",
					Port:     40000,
				},
			},
		},
	}

	fakeServiceList := []*v1.Service{testNodePortService1, testNodePortService2, testNodePortService3, testLBService, testService}

	testcases := []struct {
		name        string
		fwCache     firewallCache
		serviceList []*v1.Service
	}{
		{
			name:        "multiple services with multiple inbound rules",
			fwCache:     newFakeFirewallCache(inboundRules),
			serviceList: fakeServiceList,
		},
		{
			name:        "zero nodeport services",
			fwCache:     newFakeFirewallCache([]godo.InboundRule{}),
			serviceList: fakeServiceList,
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			// setup
			fc := &FirewallController{
				workerFirewallTags: []string{"tag"},
			}
			rules := fc.createInboundRules(test.serviceList)

			if &rules[0].PortRange == &inboundRules[0].PortRange {
				t.Errorf("got PortRange: %q, want PortRange: %q", rules[0].PortRange, inboundRules[0].PortRange)
			}
			if &rules[0].Protocol == &inboundRules[0].Protocol {
				t.Errorf("got Protocol: %q, want Protocol: %q", rules[0].Protocol, inboundRules[0].Protocol)
			}
			if diff := cmp.Diff(rules[0], inboundRules[0]); diff != "" {
				t.Errorf("got rules: %v, want rules: %v", rules[0], inboundRules[0])
			}
		})
	}
}

func TestFirewallController_NoDataRace(t *testing.T) {
	// setup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	gclient := newFakeGodoClient(
		&fakeFirewallService{
			listFunc: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
			updateFunc: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			createFunc: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
			getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
		},
	)
	fwManagerOp := newFakeFirewallManagerOp(gclient, newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}))
	fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, []string{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil { // context has not been terminated
			if err := fc.ensureReconciledFirewall(ctx); err != nil && err != context.Canceled {
				t.Errorf("ensureReconciledFirewall failed: %s", err)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fc.Run(ctx.Done(), fwManagerOp, time.Duration(0))
	}()

	wg.Wait()
	// We do not assert on anything because the goal of this test is to catch data races.
}

// func TestFirewallController_runCallsCreateWhenFirewallDoesNotExist(t *testing.T) {

// }

// func TestFirewallController_runWithModifiedFirewall(t *testing.T) {
// rules field
// name field
// }
