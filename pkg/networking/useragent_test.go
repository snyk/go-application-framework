package networking

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_TestUserAgentInfoString(t *testing.T) {
	ua := aUserAgent()

	expected := "snyk-ls/v20230726.103310-SNAPSHOT-19462ef (darwin;arm64) EMACS/(emacs/GNU Emacs 29.0.91 (build 1, aarch64-apple-darwin22.4.0, NS appkit-2299.50 Version 13.3.1 (Build 22E261)) of 2023-06-01) (snyk-ls/v20230726.103310-SNAPSHOT-19462ef)"

	actual := ua.String()

	if actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}
}

func Test_TestUserAgentInfoString_NoContainsNewLine(t *testing.T) {
	actual := aUserAgent()

	actual.App += "\r\n"
	actual.AppVersion += "\r\n"
	actual.Integration += "\r\n"
	actual.IntegrationVersion += "\r\n"
	actual.IntegrationEnvironment += "\r\n"
	actual.IntegrationEnvironmentVersion += "\r\n"
	actual.OS += "\r\n"
	actual.Arch += "\r\n"

	assert.Equal(t, "snyk-ls /v20230726.103310-SNAPSHOT-19462ef  (darwin ;arm64 ) EMACS /(emacs/GNU Emacs 29.0.91 (build 1, aarch64-apple-darwin22.4.0, NS appkit-2299.50 Version 13.3.1 (Build 22E261)) of 2023-06-01)  (snyk-ls /v20230726.103310-SNAPSHOT-19462ef )", actual.String())
}

func aUserAgent() UserAgentInfo {
	ua := UserAgentInfo{
		App:                           "snyk-ls",
		AppVersion:                    "v20230726.103310-SNAPSHOT-19462ef",
		Integration:                   "EMACS",
		IntegrationVersion:            "(emacs/GNU Emacs 29.0.91 (build 1, aarch64-apple-darwin22.4.0, NS appkit-2299.50 Version 13.3.1 (Build 22E261)) of 2023-06-01)",
		IntegrationEnvironment:        "snyk-ls",
		IntegrationEnvironmentVersion: "v20230726.103310-SNAPSHOT-19462ef",
		OS:                            "darwin",
		Arch:                          "arm64",
	}

	return ua
}
