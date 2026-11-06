package logging

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func scrubLogLine(config configuration.Configuration, message string) string {
	var output bytes.Buffer
	logger := zerolog.New(NewScrubbingWriter(zerolog.MultiLevelWriter(&output), GetScrubDictFromConfig(config)))
	logger.Info().Msg(message)
	return output.String()
}

func Test_Scrub_KnownSecretInsideUnknownTokenDoesNotUncoverTheTokenTail(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(auth.PARAMETER_CLIENT_ID, "12345678")

	output := scrubLogLine(config, "body: access_token=abcdefgh12345678ijklmnop")

	assert.NotContains(t, output, "ijklmnop")
}

func Test_Scrub_RedactionTermAfterBearerPatternIsFullyRedacted(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(REDACTION_TERMS, []string{"longprefix!tail99"})

	output := scrubLogLine(config, "Authorization: Bearer longprefix!tail99")

	assert.NotContains(t, output, "tail99")
}

func Test_Scrub_SecretWithCharactersThatJSONEscapesIsRedacted(t *testing.T) {
	for name, secret := range map[string]string{"quote": `abc"defghijk`, "backslash": `abc\defghijk`} {
		t.Run(name, func(t *testing.T) {
			config := configuration.NewInMemory()
			config.Set(auth.PARAMETER_CLIENT_SECRET, secret)

			output := scrubLogLine(config, "secret="+secret)

			assert.NotContains(t, output, "defghijk")
		})
	}
}

func Test_Scrub_PEMClientSecretIsRedacted(t *testing.T) {
	const keyLine = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"
	pem := "-----BEGIN PRIVATE KEY-----\n" + keyLine + "\n-----END PRIVATE KEY-----\n"
	config := configuration.NewInMemory()
	config.Set(auth.PARAMETER_CLIENT_SECRET, pem)

	t.Run("whole key", func(t *testing.T) {
		assert.NotContains(t, scrubLogLine(config, "secret: "+pem), keyLine)
	})
	t.Run("one line of the key", func(t *testing.T) {
		assert.NotContains(t, scrubLogLine(config, "line: "+keyLine), keyLine)
	})
}
