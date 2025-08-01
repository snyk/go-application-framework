package fips_enable

import "testing"

func Test_setFipState(t *testing.T) {
	tests := []struct {
		name          string
		existingValue string
		enabled       bool
		expected      string
	}{
		{
			name:          "empty value with enabled=true",
			existingValue: "",
			enabled:       true,
			expected:      "fips140=on",
		},
		{
			name:          "empty value with enabled=false",
			existingValue: "",
			enabled:       false,
			expected:      "fips140=off",
		},
		{
			name:          "existing value with enabled=true",
			existingValue: "other=value",
			enabled:       true,
			expected:      "fips140=on,other=value",
		},
		{
			name:          "existing value with enabled=false",
			existingValue: "other=value",
			enabled:       false,
			expected:      "fips140=off,other=value",
		},
		{
			name:          "multiple existing values with enabled=true",
			existingValue: "value1=test,value2=example",
			enabled:       true,
			expected:      "fips140=on,value1=test,value2=example",
		},
		{
			name:          "multiple existing values with enabled=false",
			existingValue: "value1=test,value2=example",
			enabled:       false,
			expected:      "fips140=off,value1=test,value2=example",
		},
		{
			name:          "existing value with comma prefix",
			existingValue: ",other=value",
			enabled:       true,
			expected:      "fips140=on,,other=value",
		},
		{
			name:          "existing value with comma prefix and enabled=false",
			existingValue: ",other=value",
			enabled:       false,
			expected:      "fips140=off,,other=value",
		},
		{
			name:          "whitespace in existing value",
			existingValue: " other=value ",
			enabled:       true,
			expected:      "fips140=on, other=value ",
		},
		{
			name:          "whitespace in existing value with enabled=false",
			existingValue: " other=value ",
			enabled:       false,
			expected:      "fips140=off, other=value ",
		},
		{
			name:          "complex existing value",
			existingValue: "http2server=0,http2client=0",
			enabled:       true,
			expected:      "fips140=on,http2server=0,http2client=0",
		},
		{
			name:          "complex existing value with enabled=false",
			existingValue: "http2server=0,http2client=0",
			enabled:       false,
			expected:      "fips140=off,http2server=0,http2client=0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := setFipState(tt.existingValue, tt.enabled)
			if result != tt.expected {
				t.Errorf("setFipState(%q, %t) = %q, want %q", tt.existingValue, tt.enabled, result, tt.expected)
			}
		})
	}
}
