package analytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCategorizeCliArgs(t *testing.T) {
	// Test Data Setup
	testCases := []struct {
		name           string
		args           []string
		expectedOutput []string
		expectedError  error
	}{
		// Happy Path Tests (Valid Commands & Flags)
		{"OSS test", []string{"snyk", "test"}, []string{"oss", "test"}, nil},
		{"OSS test with unmanaged flag", []string{"snyk", "test", "--unmanaged"}, []string{"oss", "test", "unmanaged"}, nil},
		{"Code test", []string{"snyk", "code", "test"}, []string{"code", "test"}, nil},
		{"IAC describe", []string{"snyk", "iac", "describe"}, []string{"iac", "describe"}, nil},
		{"IAC rules test", []string{"snyk", "iac", "rules", "test"}, []string{"iac", "rules", "test"}, nil},
		{"OSS sbom", []string{"snyk", "sbom"}, []string{"sbom"}, nil},
		{"Container sbom with all-projects flag", []string{"snyk", "container", "sbom", "--all-projects"}, []string{"container", "sbom", "all-projects"}, nil},
		{"Command with debug flag", []string{"snyk", "test", "--debug"}, []string{"oss", "test", "debug"}, nil},

		// Real-World Example with Mixed Input
		{"Mixed flags and commands", []string{"snyk", "-d", "test", "../folder/", "--org=myorg", "--remote-repo-url", "https://github.com/snyk"}, []string{"oss", "test", "org", "remote-repo-url"}, nil},
		{"Mixed wrong flags value and commands", []string{"snyk", "-d", "test", "../folder/", "--org=+myorg", "--remote-repo-url", "https://github.com/snyk"}, []string{"oss", "test", "org", "remote-repo-url"}, nil},
		{"Mixed wrong flags and commands", []string{"snyk", "-d", "test", "../folder/", "--org+=myorg", "--remote-repo-url", "https://github.com/snyk"}, []string{"oss", "test", "remote-repo-url"}, nil},

		// Missing or Invalid Commands
		{"Invalid command", []string{"snyk", "invalid"}, []string{}, nil},
		{"Invalid subcommand", []string{"snyk", "iac", "invalid"}, []string{"iac"}, nil},
		{"Missing command", []string{"snyk"}, []string{}, nil}, // Empty output for no command
		{"Valid command line ending parse check invalid flag", []string{"snyk", "test", "--", "--Dverbose=1"}, []string{"oss", "test"}, nil},
		{"Valid command line ending parse check allowlisted flag", []string{"snyk", "test", "--", "--debug=1"}, []string{"oss", "test"}, nil},
		{"Invalid commandline ending check with invalid flag", []string{"snyk", "tests", "--", "--Dverbose=1"}, []string{}, nil},

		// Unsupported Flags (Should be Omitted)
		{"Unsupported flag", []string{"snyk", "test", "--unsupported"}, []string{"oss", "test"}, nil},
		{"Unsupported flag with valid ones", []string{"snyk", "test", "--unmanaged", "--unsupported"}, []string{"oss", "test", "unmanaged"}, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute the function under test
			categories := ParseCliArgs(tc.args, KNOWN_COMMANDS, ALLOWED_FLAGS, PRODUCTS)

			// Assertions
			assert.Equal(t, tc.expectedOutput, categories)
		})
	}
}
