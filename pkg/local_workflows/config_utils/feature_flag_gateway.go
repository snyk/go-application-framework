package config_utils

import (
	"errors"
	"fmt"
	"maps"
	"slices"
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

var registryMu sync.Mutex

type flagRegistry struct {
	mu       sync.RWMutex
	flags    map[string]struct{}
	orgFetch sync.Map
}

type orgFetchResult struct {
	mu     sync.Mutex
	values map[string]bool
	done   bool
}

func getOrCreateRegistry(config configuration.Configuration) *flagRegistry {
	registryMu.Lock()
	defer registryMu.Unlock()

	if v := config.Get(registryConfigKey); v != nil {
		if r, ok := v.(*flagRegistry); ok {
			return r
		}
	}
	r := &flagRegistry{flags: make(map[string]struct{})}
	config.Set(registryConfigKey, r)
	return r
}

func (r *flagRegistry) addFlags(flags []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range flags {
		r.flags[f] = struct{}{}
	}
}

func (r *flagRegistry) allFlags() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]string, 0, len(r.flags))
	for f := range r.flags {
		result = append(result, f)
	}
	sort.Strings(result)
	return result
}

func (r *flagRegistry) resolve(c configuration.Configuration, engine workflow.Engine, orgID string, flagName string) (bool, error) {
	fetchI, _ := r.orgFetch.LoadOrStore(orgID, &orgFetchResult{})
	f := fetchI.(*orgFetchResult)

	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.done {
		allFlags := r.allFlags()
		var err error
		f.values, err = areFeaturesEnabled(c, engine, orgID, allFlags...)
		if err != nil {
			return false, fmt.Errorf("check feature flags batch: %w", err)
		}
		f.done = true
	}

	return f.values[flagName], nil
}

func AddFeatureFlagsToConfig(
	engine workflow.Engine,
	configKeyToFlag map[string]string,
) {
	config := engine.GetConfiguration()
	registry := getOrCreateRegistry(config)

	newFlags := slices.Collect(maps.Values(configKeyToFlag))
	registry.addFlags(newFlags)

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
