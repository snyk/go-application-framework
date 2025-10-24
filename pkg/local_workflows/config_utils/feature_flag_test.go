package config_utils

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_AddFeatureFlagToConfig_CacheDependentOnOrg(t *testing.T) {
	testConfigKey := "test_feature_flag"
	testutils.CheckCacheRespectOrgDependency(
		t,
		testConfigKey,
		func(isFirstCall bool) any {
			return map[string]bool{
				"ok": isFirstCall,
			}
		},
		func(engine workflow.Engine) configuration.DefaultValueFunction {
			AddFeatureFlagToConfig(engine, testConfigKey, "testFeatureFlag")
			return nil
		},
		true,
		false,
	)
}
