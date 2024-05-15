package utils

import (
	"os"

	"github.com/snyk/go-application-framework/pkg/utils"
)

var (
	// ciEnvironments is a list of environment variables that indicate a CI environment.
	// it is used to determine if the command is running in a CI environment.
	ciEnvironments = []string{
		"SNYK_CI",
		"CI",
		"CONTINUOUS_INTEGRATION",
		"BUILD_ID",
		"BUILD_NUMBER",
		"TEAMCITY_VERSION",
		"TRAVIS",
		"CIRCLECI",
		"JENKINS_URL",
		"HUDSON_URL",
		"bamboo.buildKey",
		"PHPCI",
		"GOCD_SERVER_HOST",
		"BUILDKITE",
		"TF_BUILD",
		"SYSTEM_TEAMFOUNDATIONSERVERURI", // for Azure DevOps Pipelines
	}
)

func IsCiEnvironment() bool {
	result := false

	envMap := utils.ToKeyValueMap(os.Environ(), "=")
	for i := range ciEnvironments {
		if _, ok := envMap[ciEnvironments[i]]; ok {
			result = true
			break
		}
	}

	return result
}
