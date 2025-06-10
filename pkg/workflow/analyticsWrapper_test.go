package workflow

import (
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
	assert.Equal(t, "Bar", extension["myprefix::foo"])
	assert.Equal(t, true, extension["myprefix::booleanvalue"])
	assert.Equal(t, 2, int(extension["myprefix::num"].(float64))) // there is a bit of type confusion in this test, as an internal json representation loses track of the exact type and assumes float
}
