package config_utils

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/google/uuid"

	featureflaggateway "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var evaluateFlags = featureflaggateway.EvaluateFlags
var errInvalidEvaluateFlagsResponse = errors.New("invalid evaluateFlags response")

const registryConfigKey = "hidden_feature_flag_registry"

// registryMu guards the get-or-create of a registry, because Configuration
// offers no atomic equivalent. It holds no state of its own.
var registryMu sync.Mutex

// fetchKey scopes lookup results. The API endpoint is part of the key because
// cloned configurations may address different endpoints while sharing an org.
type fetchKey struct {
	orgID  string
	apiURL string
}

// flagRegistry collects every flag registered against one configuration, so that
// an access can look all of them up in a single request.
type flagRegistry struct {
	mu sync.RWMutex
	// flags maps a flag name to the configuration key it backs.
	flags    map[string]string
	orgFetch map[fetchKey]*orgFetchResult
}

// registeredFlag is a remote feature flag together with the configuration key it
// backs.
type registeredFlag struct {
	name      string
	configKey string
}

// orgFetchResult memorizes the flags already looked up for one fetchKey. A flag
// present in values has been looked up, an absent one still needs fetching.
type orgFetchResult struct {
	mu     sync.Mutex
	values map[string]bool
}

func getOrCreateRegistry(config configuration.Configuration) *flagRegistry {
	registryMu.Lock()
	defer registryMu.Unlock()

	if registry, ok := config.Get(registryConfigKey).(*flagRegistry); ok {
		return registry
	}

	registry := &flagRegistry{
		flags:    make(map[string]string),
		orgFetch: make(map[fetchKey]*orgFetchResult),
	}

	// The registry is registered as an immutable default rather than being set as
	// a value, so that it never enters the configuration's value space where it
	// could be persisted or shadowed.
	config.AddDefaultValue(registryConfigKey, configuration.ImmutableDefaultValueFunction(registry))

	return registry
}

func (r *flagRegistry) addFlags(configKeyToFlag map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for configKey, flagName := range configKeyToFlag {
		r.flags[flagName] = configKey
	}
}

func (r *flagRegistry) allFlags() []registeredFlag {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]registeredFlag, 0, len(r.flags))
	for flagName, configKey := range r.flags {
		result = append(result, registeredFlag{name: flagName, configKey: configKey})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func (r *flagRegistry) fetchResultFor(key fetchKey) *orgFetchResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, ok := r.orgFetch[key]
	if !ok {
		result = &orgFetchResult{values: make(map[string]bool)}
		r.orgFetch[key] = result
	}
	return result
}

// resolve returns the value of flagName and looks up every flag that is
// registered but not yet known in a single request. Flags registered after an
// earlier lookup are picked up here, flags already looked up are not requested
// again, and neither are flags whose configuration key is locally overridden.
func (r *flagRegistry) resolve(c configuration.Configuration, engine workflow.Engine, orgID string, flagName string) (bool, error) {
	fetched := r.fetchResultFor(fetchKey{orgID: orgID, apiURL: c.GetString(configuration.API_URL)})

	fetched.mu.Lock()
	defer fetched.mu.Unlock()

	if value, known := fetched.values[flagName]; known {
		return value, nil
	}

	missing := make([]string, 0)
	for _, flag := range r.allFlags() {
		if _, known := fetched.values[flag.name]; known {
			continue
		}

		// A key that already holds a value never consults its default value
		// function, so evaluating its flag remotely would report an exposure for a
		// value nobody reads. The flag this call is for is exempt: it is being
		// resolved right now, which means its key has no value.
		if flag.name != flagName && c.IsSet(flag.configKey) {
			continue
		}

		missing = append(missing, flag.name)
	}

	// Requesting no flags at all would be rejected by the gateway and, since
	// nothing would be memorized, repeated on every single access.
	if len(missing) == 0 {
		return false, nil
	}

	values, err := areFeaturesEnabled(c, engine, orgID, missing...)
	if err != nil {
		return false, fmt.Errorf("check feature flags batch: %w", err)
	}

	// Every requested flag is memorized, including the ones the gateway did not
	// return, so that an unknown flag resolves to false instead of being
	// requested again on every access.
	for _, name := range missing {
		fetched.values[name] = values[name]
	}

	return fetched.values[flagName], nil
}

// AddFeatureFlagsToConfig registers configuration keys that are backed by remote
// feature flags. Flags are looked up lazily: the first access to any of them
// looks up every flag registered so far in a single request, and flags
// registered afterwards are picked up by the next access that needs them.
//
// A key that already holds a value keeps it, and its flag is left out of the
// batch another key triggers, so it is not evaluated remotely for nothing. Two
// limits apply. The value has to be there before the first flag is resolved -
// an override applied later cannot unsend a request. And the batch is narrowed
// via Configuration.IsSet, which answers a slightly narrower question than the
// callback's own "does this key already have a value": it does not see a value
// that only a pflag default or a non-last alternative key provides. Such a key
// still keeps its value, its flag is merely evaluated needlessly.
//
// Registration has to happen before a configuration is cloned. Clone copies the
// default value functions that exist at that moment, so a configuration cloned
// before a flag is registered resolves that flag to false.
func AddFeatureFlagsToConfig(
	engine workflow.Engine,
	configKeyToFlag map[string]string,
) {
	config := engine.GetConfiguration()
	registry := getOrCreateRegistry(config)
	registry.addFlags(configKeyToFlag)

	for configKey, flagName := range configKeyToFlag {
		err := config.AddKeyDependency(configKey, configuration.ORGANIZATION)
		if err != nil {
			engine.GetLogger().Err(err).Msgf("failed to add dependency for %s", configKey)
		}

		callback := func(c configuration.Configuration, existingValue any) (any, error) {
			if existingValue != nil {
				return existingValue, nil
			}

			orgID := c.GetString(configuration.ORGANIZATION)
			return registry.resolve(c, engine, orgID, flagName)
		}
		config.AddDefaultValue(configKey, callback)
	}
}

func areFeaturesEnabled(
	config configuration.Configuration,
	engine workflow.Engine,
	orgID string,
	flags ...string,
) (map[string]bool, error) {
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, err
	}

	resp, err := evaluateFlags(config, engine, flags, orgUUID)
	if err != nil {
		return nil, err
	}

	if !validEvaluateFlagsResponse(resp) {
		return nil, errInvalidEvaluateFlagsResponse
	}

	results := make(map[string]bool, len(flags))
	evaluations := resp.ApplicationvndApiJSON200.Data.Attributes.Evaluations
	for _, e := range evaluations {
		if e.Value != nil {
			results[e.Key] = *e.Value
		}
	}

	return results, nil
}

func validEvaluateFlagsResponse(resp *v20241015.ListFeatureFlagsResponse) bool {
	return resp != nil &&
		resp.ApplicationvndApiJSON200 != nil &&
		resp.ApplicationvndApiJSON200.Data != nil
}
