package contributorbilling

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ApplyFromConfiguration returns a copy of opts with unset network fields filled from configuration and engine.
// Explicit HTTPClient, IngestURL, and AuthHeader values are left unchanged.
func ApplyFromConfiguration(opts EmitOptions, config configuration.Configuration, engine workflow.Engine) EmitOptions {
	if opts.HTTPClient == nil && engine != nil {
		opts.HTTPClient = engine.GetNetworkAccess().GetHttpClient()
	}
	trimmedURL := strings.TrimSpace(opts.IngestURL)
	if trimmedURL == "" && config != nil {
		opts.IngestURL = config.GetString(configuration.API_URL)
	} else if trimmedURL != opts.IngestURL {
		opts.IngestURL = trimmedURL
	}
	trimmedAuth := strings.TrimSpace(opts.AuthHeader)
	if trimmedAuth == "" && config != nil {
		opts.AuthHeader = auth.GetAuthHeader(config)
	} else if trimmedAuth != opts.AuthHeader {
		opts.AuthHeader = trimmedAuth
	}
	return opts
}
