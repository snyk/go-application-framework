package workflow

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/analytics"
)

func TestNewAnalyticsWrapper(t *testing.T) {
	baseAnalytics := analytics.New()
	wrapper := NewAnalyticsWrapper(baseAnalytics, "MyPrefix")
	wrapper.AddExtensionStringValue("FOO", "Bar")
	wrapper.AddExtensionIntegerValue("num", 2)
	wrapper.AddExtensionBoolValue("booleanValue", true)

	obj, err := analytics.GetV2InstrumentationObject(baseAnalytics.GetInstrumentation())
	assert.NoError(t, err)
	extension := *obj.Data.Attributes.Interaction.Extension
	assert.Equal(t, "Bar", extension["MyPrefix::FOO"])
	assert.Equal(t, true, extension["MyPrefix::booleanValue"])
	assert.Equal(t, 2, int(extension["MyPrefix::num"].(float64))) //nolint:errcheck // there is a bit of type confusion in this test, as an internal json representation loses track of the exact type and assumes float
}

func TestAnalyticsWrapper_Setter(t *testing.T) {
	originalAnalytics := analytics.New()
	wrappedAnalytics := analytics.New()
	wrapper := NewAnalyticsWrapper(wrappedAnalytics, "MyPrefix")

	cmd := []string{"foo", "bar"}
	org := "org1"
	version := "1.2.3"
	api := "https://api.example.com"
	integrationName := "my-integration"
	integrationVersion := "1.0.0"
	cmdName := "cmd"
	os := "windows"
	header := func() http.Header {
		return http.Header{"foo": []string{"bar"}}
	}

	originalAnalytics.SetCmdArguments(cmd)
	originalAnalytics.SetOrg(org)
	originalAnalytics.SetVersion(version)
	originalAnalytics.SetApiUrl(api)
	originalAnalytics.SetIntegration(integrationName, integrationVersion)
	originalAnalytics.SetCommand(cmdName)
	originalAnalytics.SetOperatingSystem(os)
	originalAnalytics.AddError(errors.New("failure"))
	originalAnalytics.AddHeader(header)

	wrapper.SetCmdArguments(cmd)
	wrapper.SetOrg(org)
	wrapper.SetVersion(version)
	wrapper.SetApiUrl(api)
	wrapper.SetIntegration(integrationName, integrationVersion)
	wrapper.SetCommand(cmdName)
	wrapper.SetOperatingSystem(os)
	wrapper.AddError(errors.New("failure"))
	wrapper.AddHeader(header)

	originalImpl, ok := originalAnalytics.(*analytics.AnalyticsImpl)
	assert.True(t, ok)

	wrapperImpl, ok := wrappedAnalytics.(*analytics.AnalyticsImpl)
	assert.True(t, ok)

	originalOutput := originalImpl.GetOutputData()
	wrappedOutput := wrapperImpl.GetOutputData()

	// unset dynamically generated value
	originalOutput.Id = ""
	wrappedOutput.Id = ""
	originalOutput.DurationMs = 1
	wrappedOutput.DurationMs = 1

	assert.Equal(t, originalOutput, wrappedOutput)
}
