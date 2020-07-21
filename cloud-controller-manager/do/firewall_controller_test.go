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
			Tags:       []string{"my-tag1"},
			DropletIDs: []int{1},
		},
	}

	diffFakeInboundRule = godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "32000",
		Sources: &godo.Sources{
			Tags:       []string{"my-tag3"},
			DropletIDs: []int{1, 2},
		},
	}

	fwManagerOp FirewallManager
)

// fakeFirewallService concrete type that satisfies the FirewallsService interface.
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

func newFakeFirewallCache(inboundRule godo.InboundRule) firewallCache {
	return firewallCache{
		mu: new(sync.RWMutex),
		firewall: &godo.Firewall{
			ID:           "123",
			Name:         fakeWorkerFWName,
			InboundRules: []godo.InboundRule{inboundRule},
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
			fwCache: newFakeFirewallCache(fakeInboundRule),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errFailedToRetrieveFirewallByID
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, nil, nil
			},
			expectedError: errFailedToRetrieveFirewallByID,
		},
		{
			name:    "return error when error on List firewalls",
			fwCache: newFakeFirewallCache(fakeInboundRule),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errFailedToRetrieveFirewallList
			},
			expectedError: errFailedToRetrieveFirewallList,
		},
		{
			name:    "fail when there is no ID or firewall name match in firewall list",
			fwCache: newFakeFirewallCache(fakeInboundRule),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
		},
		{
			name:    "handle 404 response code from GET firewall by ID and instead return firewall from List",
			fwCache: newFakeFirewallCache(fakeInboundRule),
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
			fwCache: newFakeFirewallCache(fakeInboundRule),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			expectedFirewall: newFakeFirewall(fakeWorkerFWName, fakeInboundRule),
		},
		{
			name:    "when cache does not exist",
			fwCache: newFakeFirewallCache(fakeInboundRule),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
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
		name                             string
		fwCache                          firewallCache
		inboundRules                     []godo.InboundRule
		expectedGodoFirewallAddRulesResp func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
		expectedGodoFirewallCreateResp   func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallGetResp      func(context.Context, string) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallListResp     func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
		expectedGodoFirewallUpdateResp   func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedError                    error
		expectedFirewall                 *godo.Firewall
	}{
		{
			name:    "create firewall when cache does not exist (i.e. initial startup)",
			fwCache: newFakeFirewallCacheEmpty(),
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{}, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
		},
		{
			name:         "failing to update the firewall because it is missing",
			fwCache:      newFakeFirewallCache(diffFakeInboundRule),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errors.New("firewall missing")
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(fakeWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), errors.New("firewall missing")
			},
			expectedError: errFailedToCreateFirewallOnUpdate,
		},
		{
			name:         "return error when failing to add inbound rules on update request to firewall API",
			fwCache:      newFakeFirewallCache(diffFakeInboundRule),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(fakeWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), errFailedToAddInboundRules
			},
			expectedError: errFailedToAddInboundRules,
		},
		{
			name:         "when the firewall cache is nil return existing firewall from API then update cache",
			fwCache:      newFakeFirewallCacheEmpty(),
			inboundRules: []godo.InboundRule{fakeInboundRule},
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(fakeWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					listFunc:     test.expectedGodoFirewallListResp,
					addRulesFunc: test.expectedGodoFirewallAddRulesResp,
					updateFunc:   test.expectedGodoFirewallUpdateResp,
					createFunc:   test.expectedGodoFirewallCreateResp,
					getFunc:      test.expectedGodoFirewallGetResp,
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
	inboundRule := godo.InboundRule{
		Protocol:  "tcp",
		PortRange: "31220",
	}
	nodePortService := &v1.Service{
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
	fakeServiceList := []*v1.Service{nodePortService}

	testcases := []struct {
		name        string
		firewall    *godo.Firewall
		fwCache     firewallCache
		serviceList []*v1.Service
	}{
		{
			name:        "successfully updates port range",
			firewall:    nil,
			fwCache:     newFakeFirewallCache(inboundRule),
			serviceList: fakeServiceList,
		},
		{
			name:        "return node port inbound rules when we find a service of type nodeport",
			firewall:    newFakeFirewall(fakeWorkerFWName, inboundRule),
			fwCache:     newFakeFirewallCache(inboundRule),
			serviceList: fakeServiceList,
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			// setup
			gclient := newFakeGodoClient(
				&fakeFirewallService{},
			)
			inboundRules := []godo.InboundRule{inboundRule}
			fwManagerOp = newFakeFirewallManagerOp(gclient, test.fwCache)
			fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, []string{})

			rules := fc.createInboundRules(test.serviceList)
			if !cmp.Equal(rules[0].PortRange, inboundRules[0].PortRange) {
				t.Errorf("got %q, want %q", rules[0].PortRange, inboundRules[0].PortRange)
			}
			if !cmp.Equal(rules[0].Protocol, inboundRules[0].Protocol) {
				t.Errorf("got %q, want %q", rules[0].Protocol, inboundRules[0].Protocol)
			}
		})
	}
}

func TestFirewallController_run(t *testing.T) {
	testcases := []struct {
		name                           string
		fwCache                        firewallCache
		expectedGodoFirewallCreateResp func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallGetResp    func(context.Context, string) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallListResp   func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
		expectedGodoFirewallUpdateResp func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		fwReconcileFreq                time.Duration
		expectedError                  error
	}{
		{
			name:    "check for data race with high frequency",
			fwCache: newFakeFirewallCache(fakeInboundRule),
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(fakeWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			// force a high frequency to increase chance of discovering data races
			fwReconcileFreq: time.Duration(0),
		},
	}
	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			// setup
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var wg sync.WaitGroup

			gclient := newFakeGodoClient(
				&fakeFirewallService{
					listFunc:   test.expectedGodoFirewallListResp,
					updateFunc: test.expectedGodoFirewallUpdateResp,
					createFunc: test.expectedGodoFirewallCreateResp,
					getFunc:    test.expectedGodoFirewallGetResp,
				},
			)
			fwManagerOp := newFakeFirewallManagerOp(gclient, test.fwCache)
			fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, []string{})

			wg.Add(1)
			go func() {
				defer wg.Done()
				for ctx.Err() == nil { // context has not been terminated
					fc.ensureReconciledFirewall(ctx)
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				fc.Run(ctx.Done(), fwManagerOp, test.fwReconcileFreq)
			}()

			wg.Wait()
		})
	}
}
