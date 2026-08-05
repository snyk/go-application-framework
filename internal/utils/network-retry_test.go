package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_NetworkRetriesEnabled(t *testing.T) {
	tests := []struct {
		name           string
		previewEnabled bool
		retriesEnabled bool
		expected       bool
	}{
		{"neither set", false, false, false},
		{"preview only", true, false, true},
		{"opt-in only", false, true, true},
		{"both set", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			config.Set(configuration.PREVIEW_FEATURES_ENABLED, tt.previewEnabled)
			config.Set(configuration.NETWORK_REQUEST_RETRIES_ENABLED, tt.retriesEnabled)

			assert.Equal(t, tt.expected, NetworkRetriesEnabled(config))
		})
	}
}
