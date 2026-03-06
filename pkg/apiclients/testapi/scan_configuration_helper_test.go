package testapi

import (
	"reflect"
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
			name: "Secrets configuration returns secret",
			config: &ScanConfiguration{
				Secrets: &SecretsScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSecret},
		},
		{
			name: "multiple configurations returns multiple types",
			config: &ScanConfiguration{
				Sca:     &ScaScanConfiguration{},
				Sast:    &SastScanConfiguration{},
				Secrets: &SecretsScanConfiguration{},
			},
			expected: []FindingType{FindingTypeSca, FindingTypeSast, FindingTypeSecret},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetDefaultFindingTypes()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestScanConfiguration_AllFieldsHandled uses reflection to verify that all pointer fields
// in ScanConfiguration are handled by GetDefaultFindingTypes.
// This test will fail if a new scan type field is added to ScanConfiguration,
// reminding developers to update GetDefaultFindingTypes accordingly.
func TestScanConfiguration_AllFieldsHandled(t *testing.T) {
	configType := reflect.TypeOf(ScanConfiguration{})

	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)

		// Only check pointer fields (scan configuration fields are pointers)
		if field.Type.Kind() != reflect.Pointer {
			continue
		}

		// Create a ScanConfiguration with only this field set
		scanConfig := &ScanConfiguration{}
		fieldValue := reflect.ValueOf(scanConfig).Elem().FieldByName(field.Name)

		// Create a zero value of the field's element type and set it
		fieldValue.Set(reflect.New(field.Type.Elem()))

		// Call GetDefaultFindingTypes and verify it returns something
		result := scanConfig.GetDefaultFindingTypes()
		if len(result) == 0 {
			t.Errorf("ScanConfiguration field %q is not handled by GetDefaultFindingTypes. "+
				"Please update GetDefaultFindingTypes to handle this new scan type.", field.Name)
		}
	}
}
