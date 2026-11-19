package testapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanConfiguration_GetDefaultFindingTypes(t *testing.T) {
	tests := []struct {
		name     string
		config   *ScanConfiguration
		expected []FindingType
	}{
		{
			name:     "nil configuration returns nil",
			config:   nil,
			expected: nil,
		},
		{
			name:     "empty configuration returns nil",
			config:   &ScanConfiguration{},
			expected: nil,
		},
		{
			name: "SCA configuration returns sca",
			config: &ScanConfiguration{
				Sca: &ScaScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSca},
		},
		{
			name: "SAST configuration returns sast",
			config: &ScanConfiguration{
				Sast: &SastScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSast},
		},
		{
			name: "IaC configuration returns config",
			config: &ScanConfiguration{
				Iac: &IacScanConfiguration{},
			},
			expected: []FindingType{FindingTypeConfig},
		},
		{
			name: "Container configuration returns sca",
			config: &ScanConfiguration{
				Container: &ContainerScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSca},
		},
		{
			name: "Secrets configuration returns secrets",
			config: &ScanConfiguration{
				Secrets: &SecretsScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSecrets},
		},
		{
			name: "Rift configuration returns rift",
			config: &ScanConfiguration{
				Rift: &RiftScanConfiguration{},
			},
			expected: []FindingType{FindingTypeRift},
		},
		{
			name: "multiple configurations returns multiple types",
			config: &ScanConfiguration{
				Sca:     &ScaScanConfiguration{},
				Sast:    &SastScanConfiguration{},
				Secrets: &SecretsScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSca, FindingTypeSast, FindingTypeSecrets},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetDefaultFindingTypes()
			assert.Equal(t, tt.expected, result)
		})
	}
}
