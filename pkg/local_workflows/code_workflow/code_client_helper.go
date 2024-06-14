package code_workflow

import (
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

var defaultSnykCodeTimeout = 12 * time.Hour

type codeClientConfig struct {
	localConfiguration configuration.Configuration
}

func (c *codeClientConfig) Organization() string {
	return c.localConfiguration.GetString(configuration.ORGANIZATION)
}

func (c *codeClientConfig) IsFedramp() bool {
	return c.localConfiguration.GetBool(configuration.IS_FEDRAMP)
}

func (c *codeClientConfig) SnykCodeApi() string {
	return strings.Replace(c.localConfiguration.GetString(configuration.API_URL), "api", "deeproxy", -1)
}

func (c *codeClientConfig) SnykApi() string {
	return c.localConfiguration.GetString(configuration.API_URL)
}

func (c *codeClientConfig) SnykCodeAnalysisTimeout() time.Duration {
	if !c.localConfiguration.IsSet(configuration.TIMEOUT) {
		return defaultSnykCodeTimeout
	}
	timeoutInSeconds := c.localConfiguration.GetInt(configuration.TIMEOUT)
	return time.Duration(timeoutInSeconds) * time.Second
}
