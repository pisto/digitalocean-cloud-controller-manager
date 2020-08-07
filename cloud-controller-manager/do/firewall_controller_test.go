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
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

var (
	ctx = context.TODO()

	kclient kubernetes.Interface

	inf = informers.NewSharedInformerFactory(kclient, 0)

	testWorkerFWName  = "k8s-test-firewall"
	testWorkerFWTags  = []string{"tag1", "tag2"}
	testOutboundRules = []godo.OutboundRule{
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
		ID:            "123",
		Name:          workerFirewallName,
		Tags:          testWorkerFWTags,
		InboundRules:  []godo.InboundRule{inboundRule},
		OutboundRules: testOutboundRules,
	}
}

func newFakeFirewallManagerOp(client *godo.Client, cache firewallCache) *firewallManagerOp {
	return &firewallManagerOp{
		client:             client,
		fwCache:            cache,
		workerFirewallName: testWorkerFWName,
		workerFirewallTags: testWorkerFWTags,
	}
}

func newFakeFirewallCache(inboundRules []godo.InboundRule) firewallCache {
	return firewallCache{
		mu: new(sync.RWMutex),
		firewall: &godo.Firewall{
			ID:            "123",
			Name:          testWorkerFWName,
			Tags:          testWorkerFWTags,
			InboundRules:  inboundRules,
			OutboundRules: testOutboundRules,
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
				return nil, newFakeNotOKResponse(), errors.New("failed to retrieve firewall by ID")
			},
			expectedError: errors.New("failed to retrieve firewall by ID"),
		},
		{
			name:    "return error when error on List firewalls",
			fwCache: newFakeFirewallCacheEmpty(),
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errors.New("failed to retrieve list of firewalls from DO API")
			},
			expectedError: errors.New("failed to retrieve list of firewalls from DO API"),
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
				return []godo.Firewall{*newFakeFirewall(testWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedFirewall: newFakeFirewall(testWorkerFWName, fakeInboundRule),
		},
		{
			name:    "get firewall from API with cached firewall ID",
			fwCache: newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}),
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(testWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			expectedFirewall: newFakeFirewall(testWorkerFWName, fakeInboundRule),
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
			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("incorrect firewall config\nwant: %#v\n got: %#v", test.expectedError, err)
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
		firewallRequest                  *godo.FirewallRequest
		expectedGodoFirewallCreateResp   func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallGetResp      func(context.Context, string) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallListResp     func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
		expectedGodoFirewallUpdateResp   func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallAddRulesResp func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
		expectedError                    error
		expectedFirewall                 *godo.Firewall
	}{
		{
			name:    "do nothing when firewall is already properly configured",
			fwCache: newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}),
			firewallRequest: &godo.FirewallRequest{
				Name:          testWorkerFWName,
				InboundRules:  []godo.InboundRule{fakeInboundRule},
				OutboundRules: testOutboundRules,
				Tags:          testWorkerFWTags,
			},
		},
		{
			name:    "create firewall when cache does not exist (i.e. initial startup)",
			fwCache: newFakeFirewallCacheEmpty(),
			firewallRequest: &godo.FirewallRequest{
				Name:          testWorkerFWName,
				InboundRules:  []godo.InboundRule{fakeInboundRule},
				OutboundRules: testOutboundRules,
				Tags:          testWorkerFWTags,
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{}, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(testWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
		},
		{
			name:    "failing to update the firewall because of an unexpected error",
			fwCache: newFakeFirewallCache([]godo.InboundRule{diffFakeInboundRule}),
			firewallRequest: &godo.FirewallRequest{
				Name:          testWorkerFWName,
				InboundRules:  []godo.InboundRule{fakeInboundRule},
				OutboundRules: testOutboundRules,
				Tags:          testWorkerFWTags,
			},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), errors.New("unexpected error")
			},
			expectedGodoFirewallAddRulesResp: func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error) {
				return newFakeNotOKResponse(), errors.New("unexpected error")
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(testWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errors.New("unexpected error")
			},
			expectedError: errors.New("failed to create firewall"),
		},
		{
			name:    "failing to get the firewall",
			fwCache: newFakeFirewallCacheEmpty(),
			firewallRequest: &godo.FirewallRequest{
				Name:          testWorkerFWName,
				InboundRules:  []godo.InboundRule{fakeInboundRule},
				OutboundRules: testOutboundRules,
				Tags:          testWorkerFWTags,
			},
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errors.New("unexpected error")
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(testWorkerFWName, fakeInboundRule)}, newFakeNotOKResponse(), errors.New("unexpected error")
			},
			expectedError: errors.New("failed to create firewall"),
		},
		{
			name:    "return error when failing to add inbound rules on update request to firewall API",
			fwCache: newFakeFirewallCache([]godo.InboundRule{diffFakeInboundRule}),
			firewallRequest: &godo.FirewallRequest{
				Name:          testWorkerFWName,
				InboundRules:  []godo.InboundRule{fakeInboundRule},
				OutboundRules: testOutboundRules,
				Tags:          testWorkerFWTags,
			},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotOKResponse(), errors.New("failed to add inbound rules")
			},
			expectedGodoFirewallAddRulesResp: func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error) {
				return newFakeNotOKResponse(), errors.New("unexpected error")
			},
			expectedError: errors.New("failed to add inbound rules"),
		},
		{
			name:    "when the firewall cache is nil return existing firewall from API then update cache",
			fwCache: newFakeFirewallCacheEmpty(),
			firewallRequest: &godo.FirewallRequest{
				Name:          testWorkerFWName,
				InboundRules:  []godo.InboundRule{fakeInboundRule},
				OutboundRules: testOutboundRules,
				Tags:          testWorkerFWTags,
			},
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(testWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					listFunc:     test.expectedGodoFirewallListResp,
					updateFunc:   test.expectedGodoFirewallUpdateResp,
					createFunc:   test.expectedGodoFirewallCreateResp,
					getFunc:      test.expectedGodoFirewallGetResp,
					addRulesFunc: test.expectedGodoFirewallAddRulesResp,
				},
			)
			fwManagerOp = newFakeFirewallManagerOp(gclient, test.fwCache)
			fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, testWorkerFWTags, testWorkerFWName)

			err := fc.fwManager.Set(ctx, test.firewallRequest)
			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("incorrect firewall config\nwant: %#v\n got: %#v", test.expectedError, err)
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
				return newFakeFirewall(testWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			createFunc: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
			getFunc: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(testWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
			addRulesFunc: func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error) {
				return newFakeOKResponse(), nil
			},
		},
	)
	fwManagerOp := newFakeFirewallManagerOp(gclient, newFakeFirewallCache([]godo.InboundRule{fakeInboundRule}))
	fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, testWorkerFWTags, testWorkerFWName)

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

func TestFirewallController_actualRun(t *testing.T) {
	testcases := []struct {
		name                             string
		fwCache                          firewallCache
		expectedGodoFirewallCreateResp   func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallGetResp      func(context.Context, string) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallListResp     func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error)
		expectedGodoFirewallUpdateResp   func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error)
		expectedGodoFirewallAddRulesResp func(context.Context, string, *godo.FirewallRulesRequest) (*godo.Response, error)
	}{
		{
			name:    "calls create when firewall does not exist",
			fwCache: newFakeFirewallCacheEmpty(),
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallGetResp: func(context.Context, string) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeNotFoundResponse(), nil
			},
			expectedGodoFirewallCreateResp: func(context.Context, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return nil, newFakeOKResponse(), nil
			},
		},
		{
			name:    "handles a modified firewall",
			fwCache: newFakeFirewallCache([]godo.InboundRule{diffFakeInboundRule}),
			expectedGodoFirewallListResp: func(context.Context, *godo.ListOptions) ([]godo.Firewall, *godo.Response, error) {
				return []godo.Firewall{*newFakeFirewall(testWorkerFWName, fakeInboundRule)}, newFakeOKResponse(), nil
			},
			expectedGodoFirewallUpdateResp: func(context.Context, string, *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
				return newFakeFirewall(testWorkerFWName, fakeInboundRule), newFakeOKResponse(), nil
			},
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			// setup
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			gclient := newFakeGodoClient(
				&fakeFirewallService{
					listFunc:     test.expectedGodoFirewallListResp,
					updateFunc:   test.expectedGodoFirewallUpdateResp,
					createFunc:   test.expectedGodoFirewallCreateResp,
					getFunc:      test.expectedGodoFirewallGetResp,
					addRulesFunc: test.expectedGodoFirewallAddRulesResp,
				},
			)
			fwManagerOp := newFakeFirewallManagerOp(gclient, newFakeFirewallCacheEmpty())
			fc := NewFirewallController(ctx, kclient, gclient, inf.Core().V1().Services(), fwManagerOp, testWorkerFWTags, testWorkerFWName)

			fc.actualRun(ctx.Done(), fwManagerOp, time.Duration(0))
		})
	}
}
