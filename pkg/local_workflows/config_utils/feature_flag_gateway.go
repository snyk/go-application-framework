package config_utils

import (
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	featureflaggateway "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var evaluateFlags = featureflaggateway.EvaluateFlags
var errInvalidEvaluateFlagsResponse = errors.New("invalid evaluateFlags response")

type flagRegistry struct {
	mu    sync.Mutex
	flags map[string]struct{}
	sf    singleflight.Group
}

func (r *flagRegistry) addFlags(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range names {
		r.flags[name] = struct{}{}
	}
}

func (r *flagRegistry) allFlags() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return utils.SortedMapKeys(r.flags)
}

// registries maps Configuration instances to their flag registry.
// Stored outside the config keyspace to avoid env-var collisions and AllKeys() pollution.
var registries sync.Map

func getFlagRegistry(config configuration.Configuration) *flagRegistry {
	if r, ok := registries.Load(config); ok {
		return r.(*flagRegistry)
	}
	return nil
}

func getOrCreateFlagRegistry(config configuration.Configuration) *flagRegistry {
	if r, ok := registries.Load(config); ok {
		return r.(*flagRegistry)
	}
	created := &flagRegistry{flags: make(map[string]struct{})}
	actual, _ := registries.LoadOrStore(config, created)
	return actual.(*flagRegistry)
}

func AddFeatureFlagsToConfig(
	engine workflow.Engine,
	configKeyToFlag map[string]string,
) {
	config := engine.GetConfiguration()
	registry := getOrCreateFlagRegistry(config)

	flagNames := make([]string, 0, len(configKeyToFlag))
	for _, flagName := range configKeyToFlag {
		flagNames = append(flagNames, flagName)
	}
	registry.addFlags(flagNames)

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
			cacheKey := fmt.Sprintf("hidden_flags_%s", orgID)

			if cached := c.Get(cacheKey); cached != nil {
				if m, ok := cached.(map[string]bool); ok {
					if _, exists := m[flagName]; exists {
						return m[flagName], nil
					}
				}
			}

			result, err, _ := registry.sf.Do(cacheKey, func() (interface{}, error) {
				allFlags := registry.allFlags()
				res, err := areFeaturesEnabled(c, engine, orgID, allFlags...)
				if err != nil {
					return nil, err
				}
				if addErr := c.AddKeyDependency(cacheKey, configuration.ORGANIZATION); addErr != nil {
					engine.GetLogger().Err(addErr).Msgf("failed to add dependency for %s", cacheKey)
				}
				c.Set(cacheKey, res)
				return res, nil
			})
			if err != nil {
				return false, fmt.Errorf("check feature flags batch: %w", err)
			}

			res := result.(map[string]bool)
			return res[flagName], nil
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
	for _, f := range flags {
		results[f] = false
	}

	evaluations := resp.ApplicationvndApiJSON200.Data.Attributes.Evaluations
	evaluated := make(map[string]struct{}, len(evaluations))
	for _, e := range evaluations {
		evaluated[e.Key] = struct{}{}
		if e.Value != nil {
			results[e.Key] = *e.Value
		}
	}

	if engine != nil {
		for _, f := range flags {
			if _, ok := evaluated[f]; !ok {
				engine.GetLogger().Debug().Msgf("feature flag %q: no evaluation returned, defaulting to false", f)
			}
		}
	}

	return results, nil
}

func validEvaluateFlagsResponse(resp *v20241015.ListFeatureFlagsResponse) bool {
	return resp != nil &&
		resp.ApplicationvndApiJSON200 != nil &&
		resp.ApplicationvndApiJSON200.Data != nil
}
