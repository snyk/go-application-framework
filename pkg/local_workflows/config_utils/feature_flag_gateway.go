package config_utils

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	featureflaggateway "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var evaluateFlags = featureflaggateway.EvaluateFlags
var errInvalidEvaluateFlagsResponse = errors.New("invalid evaluateFlags response")

//type featureFlagBatchCache struct {
//	mu     sync.Mutex
//	cache  map[string]*featureFlagBatchEntry
//	flags  []string
//	engine workflow.Engine
//}

//type featureFlagBatchEntry struct {
//	once   sync.Once
//	values map[string]bool
//	err    error
//}

func AddFeatureFlagsToConfig(
	engine workflow.Engine,
	configKeyToFlag map[string]string,
) {
	config := engine.GetConfiguration()
	flags := make([]string, 0, len(configKeyToFlag))
	for _, flag := range configKeyToFlag {
		flags = append(flags, flag)
	}
	sort.Strings(flags)

	for configKey, flagName := range configKeyToFlag {
		configKey := configKey
		flagName := flagName
		err := config.AddKeyDependency(configKey, configuration.ORGANIZATION)
		if err != nil {
			engine.GetLogger().Err(err).Msgf("failed to add dependency for %s", configKey)
		}

		callback := func(c configuration.Configuration, existingValue any) (any, error) {
			if existingValue != nil {
				return existingValue, nil
			}

			orgID := c.GetString(configuration.ORGANIZATION)
			cacheKey := fmt.Sprintf("__ffg_batch__:%s:%s", orgID, strings.Join(flags, ","))
			if cached := c.Get(cacheKey); cached != nil {
				if m, ok := cached.(map[string]bool); ok {
					return m[flagName], nil
				}
			}

			res, err := areFeaturesEnabled(c, engine, orgID, flags...)
			if err != nil {
				return false, fmt.Errorf("check feature flags batch: %w", err)
			}
			c.Set(cacheKey, res)

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
