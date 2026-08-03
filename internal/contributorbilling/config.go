package contributorbilling

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ApplyFromConfiguration fills unset network fields on opts from GAF configuration and engine.
// Explicit HTTPClient, IngestURL, and AuthHeader values on opts are left unchanged.
func ApplyFromConfiguration(opts *EmitOptions, config configuration.Configuration, engine workflow.Engine) {
	if opts == nil {
		return
	}

	if opts.HTTPClient == nil && engine != nil {
		opts.HTTPClient = engine.GetNetworkAccess().GetHttpClient()
	}
	if strings.TrimSpace(opts.IngestURL) == "" && config != nil {
		opts.IngestURL = config.GetString(configuration.API_URL)
	}
	if strings.TrimSpace(opts.AuthHeader) == "" && config != nil {
		opts.AuthHeader = auth.GetAuthHeader(config)
	}
}
