package utils

import (
	"os"

	"github.com/snyk/go-application-framework/pkg/utils"
)

var (
	// ciEnvironments is a list of environment variables that indicate a CI environment.
	// it is used to determine if the command is running in a CI environment.
	ciEnvironments = []string{
		// Generic
		"CI",
		"CI_BUILD_ID",
		"CI_COMMIT_SHA",
		"CI_JOB_ID",
		"CI_REPOSITORY_URL",
		"CI_SERVER_NAME",
		"CONTINUOUS_INTEGRATION",
		"SNYK_CI",
		// Appcircle
		"AC_APPCIRCLE",
		// AppVeyor
		"APPVEYOR",
		// AWS CodeBuild
		"CODEBUILD",
		"CODEBUILD_BUILD_ARN",
		// Azure Pipelines
		"SYSTEM_TEAMFOUNDATIONCOLLECTIONURI",
		"SYSTEM_TEAMFOUNDATIONSERVERURI",
		"SYSTEM_TEAMPROJECTID",
		"TF_BUILD",
		"AZURE_PIPELINES",
		// Bamboo
		"bamboo_planKey",
		"bamboo.buildKey",
		// Bitbucket Pipelines
		"BITBUCKET_COMMIT",
		"BITBUCKET_PIPE_STEP_RUN_UUID",
		// Bitrise
		"BITRISE_IO",
		// Buddy
		"BUDDY_WORKSPACE_ID",
		// Buildkite
		"BUILDKITE",
		"BUILDKITE_BUILD_ID",
		// CircleCI
		"CIRCLECI",
		"CIRCLE_WORKFLOW_ID",
		// Cirrus CI
		"CIRRUS_CI",
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
		"GOCD_SERVER_HOST",
		"GO_PIPELINE_LABEL",
		// Hudson
		"HUDSON_URL",
		// Jenkins
		"BUILD_ID",
		"BUILD_NUMBER",
		"BUILD_TAG",
		"JENKINS_URL",
		// LayerCI
		"LAYERCI",
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
		// Screwdriver
		"SCREWDRIVER",
		// Semaphore
		"SEMAPHORE",
		// Shippable
		"SHIPPABLE",
		// Solano CI
		"TDDIUM",
		// Strider CD
		"STRIDER",
		// TaskCluster
		"RUN_ID",
		"TASK_ID",
		// TeamCity
		"TEAMCITY_VERSION",
		// Travis CI
		"TRAVIS",
		"TRAVIS_PULL_REQUEST",
		// Vercel
		"NOW_BUILDER",
		"NOW_BUILD",
		"VERCEL",
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
