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
		"GOCD_SERVER_HOST",
		// AppVeyor
		"APPVEYOR",
		// Azure Pipelines
		"SYSTEM_TEAMFOUNDATIONCOLLECTIONURI",
		"SYSTEM_TEAMFOUNDATIONSERVERURI",
		"TF_BUILD",
		// Appcircle
		"AC_APPCIRCLE",
		// Bamboo
		"bamboo_planKey",
		"bamboo.buildKey",
		// Bitbucket Pipelines
		"BITBUCKET_COMMIT",
		// Bitrise
		"BITRISE_IO",
		// Buddy
		"BUDDY_WORKSPACE_ID",
		// Buildkite
		"BUILDKITE",
		// CircleCI
		"CIRCLECI",
		// Cirrus CI
		"CIRRUS_CI",
		// AWS CodeBuild
		"CODEBUILD_BUILD_ARN",
		// Codefresh
		"CF_BUILD_ID",
		// Drone
		"DRONE",
		// dsari
		"DSARI",
		// Expo Application Services
		"EAS_BUILD",
		// GitHub Actions
		"GITHUB_ACTIONS",
		// GitLab CI
		"GITLAB_CI",
		// GoCD
		"GO_PIPELINE_LABEL",
		// LayerCI
		"LAYERCI",
		// Hudson
		"HUDSON_URL",
		// Jenkins
		"JENKINS_URL",
		"BUILD_ID",
		"BUILD_NUMBER",
		// Magnum CI
		"MAGNUM",
		// Netlify CI
		"NETLIFY",
		// Nevercode
		"NEVERCODE",
		// PHPCI
		"PHPCI",
		// Render
		"RENDER",
		// Sail CI
		"SAILCI",
		// Semaphore
		"SEMAPHORE",
		// Screwdriver
		"SCREWDRIVER",
		// Shippable
		"SHIPPABLE",
		// Solano CI
		"TDDIUM",
		// Strider CD
		"STRIDER",
		// TaskCluster
		"TASK_ID",
		"RUN_ID",
		// TeamCity
		"TEAMCITY_VERSION",
		// Travis CI
		"TRAVIS",
		// Vercel
		"NOW_BUILDER",
		// Visual Studio App Center
		"APPCENTER_BUILD_ID",
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
