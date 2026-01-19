package config_utils

import (
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	featureflaggateway "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var evaluateFlags = featureflaggateway.EvaluateFlags
var errInvalidEvaluateFlagsResponse = errors.New("invalid evaluateFlags response")

type featureFlagBatchCache struct {
	mu     sync.Mutex
	cache  map[string]*featureFlagBatchEntry
	flags  []string
	engine workflow.Engine
}

type featureFlagBatchEntry struct {
	once   sync.Once
	values map[string]bool
	err    error
}

func AddFeatureFlagsToConfig(
	engine workflow.Engine,
	configKeyToFlag map[string]string,
) {
	config := engine.GetConfiguration()
	flags := make([]string, 0, len(configKeyToFlag))
	for _, flag := range configKeyToFlag {
		flags = append(flags, flag)
	}

	batchCache := &featureFlagBatchCache{
		cache:  make(map[string]*featureFlagBatchEntry),
		flags:  flags,
		engine: engine,
	}

	for configKey, flagName := range configKeyToFlag {
		err := config.AddKeyDependency(configKey, configuration.ORGANIZATION)
		if err != nil {
			engine.GetLogger().Err(err).Msgf("Failed to add dependency for %s", configKey)
		}

		callback := func(c configuration.Configuration, existingValue any) (any, error) {
			if existingValue != nil {
				return existingValue, nil
			}

			flagsMap, batchErr := batchCache.getBatchForOrg(c)
			if batchErr != nil {
				return false, fmt.Errorf("check feature flags batch: %w", batchErr)
			}
			return flagsMap[flagName], nil
		}
		config.AddDefaultValue(configKey, callback)
	}
}

func (c *featureFlagBatchCache) getBatchForOrg(
	cfg configuration.Configuration,
) (map[string]bool, error) {
	orgID := cfg.GetString(configuration.ORGANIZATION)

	c.mu.Lock()
	entry, ok := c.cache[orgID]
	if !ok {
		entry = &featureFlagBatchEntry{}
		c.cache[orgID] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		v, err := areFeaturesEnabled(cfg, c.engine, orgID, c.flags...)
		entry.values = v
		entry.err = err
	})

	if entry.err != nil {
		return nil, entry.err
	}
	return entry.values, nil
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

	// default missing flags to false
	for _, flag := range flags {
		if _, ok := results[flag]; !ok {
			results[flag] = false
		}
	}

	return results, nil
}

func validEvaluateFlagsResponse(resp *v20241015.ListFeatureFlagsResponse) bool {
	return resp != nil &&
		resp.ApplicationvndApiJSON200 != nil &&
		resp.ApplicationvndApiJSON200.Data != nil
}
