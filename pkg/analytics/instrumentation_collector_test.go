package analytics

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/stretchr/testify/assert"

	api "github.com/snyk/go-application-framework/internal/api/analytics/2024-03-07"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/networking"
)

var logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

func Test_InstrumentationCollector(t *testing.T) {
	t.Run("it should construct a V2 instrumentation object", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent application data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
		mockUserAgent.App = "snyk-ls"
		mockUserAgent.AppVersion = "v20240515.190857"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Application = &api.Application{
			Name:    mockUserAgent.App,
			Version: mockUserAgent.AppVersion,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent environment data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
		mockUserAgent.IntegrationEnvironment = "VScode"
		mockUserAgent.IntegrationEnvironmentVersion = "1.89"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Environment = &api.Environment{
			Name:    mockUserAgent.IntegrationEnvironment,
			Version: mockUserAgent.IntegrationEnvironmentVersion,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent integration data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
		mockUserAgent.Integration = "Snyk Security plugin for VSCode"
		mockUserAgent.IntegrationVersion = "v2.70"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Integration = &api.Integration{
			Name:    mockUserAgent.Integration,
			Version: mockUserAgent.IntegrationVersion,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent platform data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockUserAgent := networking.UserAgentInfo{}
		mockUserAgent.OS = "macos"
		mockUserAgent.Arch = "arm64"

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Platform = &api.Platform{
			Os:   mockUserAgent.OS,
			Arch: mockUserAgent.Arch,
		}

		ic.SetUserAgent(mockUserAgent)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it sets the userAgent performance data", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockDuration := 10 * time.Millisecond

		expectedV2InstrumentationObject.Data.Attributes.Runtime.Performance = &api.Performance{
			DurationMs: mockDuration.Milliseconds(),
		}

		ic.SetDuration(mockDuration)
		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should collect interaction errors", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		mockError := fmt.Errorf("oops")
		ic.AddError(mockError)

		snykError := snyk.NewBadRequestError("")
		ic.AddError(snykError)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors = toInteractionErrors([]error{mockError, snykError})
		assert.Equal(t, 1, len(*expectedV2InstrumentationObject.Data.Attributes.Interaction.Errors))

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)

		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should support all interaction extension types", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("integers", 123)
		ic.AddExtension("booleans", true)

		mockExtension := map[string]interface{}{
			"strings":  "hello world",
			"integers": 123,
			"booleans": true,
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic)
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should sanitize potential PII data put in the extension type", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("password", "hunter2")

		mockExtension := map[string]interface{}{
			"strings":  "hello world",
			"password": "***",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should shape-scrub secret-shaped extension values when WithConfiguration is supplied", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("note", "Bearer abcdef123456")

		mockExtension := map[string]interface{}{
			"strings": "hello world",
			"note":    "Bearer ***",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger), WithConfiguration(configuration.NewInMemory()))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should not stack-overflow when a shape-scrubbed extension value contains a cycle", func(t *testing.T) {
		ic := setupBaseCollector(t)

		cyclic := map[string]interface{}{"note": "Bearer abcdef123456"}
		cyclic["self"] = cyclic
		ic.AddExtension("cyclic", cyclic)

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger), WithConfiguration(configuration.NewInMemory()))
		assert.NoError(t, err)

		extension := *actualV2InstrumentationObject.Data.Attributes.Interaction.Extension
		cyclicResult, ok := extension["cyclic"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "Bearer ***", cyclicResult["note"])
		assert.Nil(t, cyclicResult["self"])
	})

	t.Run("it should not redact unrelated extension values that merely share a substring with a scrubbed secret", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("detail", "Bearer abcdef123456")
		ic.AddExtension("note", "unrelated log message mentioning abcdef123456 in passing")

		mockExtension := map[string]interface{}{
			"strings": "hello world",
			"detail":  "Bearer ***",
			"note":    "unrelated log message mentioning abcdef123456 in passing",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger), WithConfiguration(configuration.NewInMemory()))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should redact a static term embedded in freeform extension text without corrupting or under-redacting it", func(t *testing.T) {
		// Extension leaves are scrubbed via ScrubValue, not Scrub: a term adjacent to `:`/`,` or
		// fused to a digit must still be redacted verbatim, with no JSON-value quoting or digit-fusion skip.
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		cfg := configuration.NewInMemory()
		cfg.Set(logging.REDACTION_TERMS, []string{"1000"})

		ic.AddExtension("note", "port:1000,timeout:3000")
		ic.AddExtension("adjacent", "trace id 10001234 seen")

		mockExtension := map[string]interface{}{
			"strings":  "hello world",
			"note":     "port:***,timeout:3000",
			"adjacent": "trace id ***1234 seen",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger), WithConfiguration(cfg))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should not corrupt sibling fields when a short-form-keyed extension value is a nested object", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("p", map[string]interface{}{"nested": "obj"})
		ic.AddExtension("tail", "keep")

		mockExtension := map[string]interface{}{
			"strings": "hello world",
			"p":       map[string]interface{}{"nested": "obj"},
			"tail":    "keep",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger), WithConfiguration(configuration.NewInMemory()))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should leave secret-shaped extension values untouched when WithConfiguration is omitted", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		ic.AddExtension("note", "Bearer abcdef123456")

		mockExtension := map[string]interface{}{
			"strings": "hello world",
			"note":    "Bearer abcdef123456",
		}

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = &mockExtension

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	t.Run("it should remove the extension object gracefully if sanitation fails ", func(t *testing.T) {
		ic := setupBaseCollector(t)
		expectedV2InstrumentationObject := buildExpectedBaseObject(t)

		circularRef := make(map[string]interface{})
		circularRef["self"] = circularRef
		ic.AddExtension("circular", circularRef)

		expectedV2InstrumentationObject.Data.Attributes.Interaction.Extension = nil

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger))
		assert.NoError(t, err)
		expectedV2InstrumentationJson, err := json.Marshal(expectedV2InstrumentationObject)
		assert.NoError(t, err)
		actualV2InstrumentationJson, err := json.Marshal(actualV2InstrumentationObject)
		assert.NoError(t, err)

		assert.JSONEq(t, string(expectedV2InstrumentationJson), string(actualV2InstrumentationJson))
	})

	// This case reads the username from user.Current() because the seam does too, and asserts only
	// that the key survives verbatim. That holds whatever the process runs as, so a machine whose
	// user is named after some other value in the payload can't flip the result -- the failure mode
	// IDE-2499 hit in dev containers running as `dev`. What the username pass does to *values* is
	// pinned against a synthetic username in Test_SanitizeUsername_* instead.
	t.Run("it should never redact the current username inside an extension key", func(t *testing.T) {
		currentUser, err := user.Current()
		assert.NoError(t, err)

		ic := setupBaseCollector(t)
		// A short username used to rewrite this key into gaf.***.defaultfunc.organization.lookup,
		// minting a fresh field path per user (CLI-1819).
		keyPath := "gaf." + currentUser.Username + ".defaultfunc.organization.lookup"
		ic.AddExtension(keyPath, "env")

		actualV2InstrumentationObject, err := GetV2InstrumentationObject(ic, WithLogger(&logger))
		assert.NoError(t, err)

		assert.Contains(t, *actualV2InstrumentationObject.Data.Attributes.Interaction.Extension, keyPath)
	})

	t.Run("it should get the category vector", func(t *testing.T) {
		ic := setupBaseCollector(t)

		mockCategory := []string{"code", "test"}
		actualCategory := ic.GetCategory()
		assert.Equal(t, mockCategory, actualCategory)
	})
}

func setupBaseCollector(t *testing.T) InstrumentationCollector {
	t.Helper()

	ic := NewInstrumentationCollector()
	ic.SetInteractionId("interactionID")
	ic.SetTimestamp(time.Now())
	ic.SetStage("cicd")
	ic.SetType("analytics")
	ic.SetInteractionType("Scan done")
	ic.SetCategory([]string{"code", "test"})
	ic.SetStatus(Success)
	ic.SetTestSummary(*json_schemas.NewTestSummary("sast", ""))
	ic.SetTargetId("targetID")
	ic.AddExtension("strings", "hello world")
	ic.SetTimestamp(time.Date(2025, 1, 01, 0, 0, 0, 0, time.UTC))

	return ic
}

func TestAddExtension_ConcurrentSafe(t *testing.T) {
	ic := NewInstrumentationCollector()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ic.AddExtension(fmt.Sprintf("key%d", n), n)
		}(i)
	}
	wg.Wait()
}

// Helper function to build the expected response object
func buildExpectedBaseObject(t *testing.T) api.AnalyticsRequestBody {
	t.Helper()

	mockInteractionId := "interactionID"
	mockStage := "cicd"
	mockInstrumentationType := "analytics"
	mockInteractionType := "Scan done"
	mockCategory := []string{"code", "test"}
	mockStatus := Success
	mockTestSummary := json_schemas.NewTestSummary("sast", "")
	mockTargetId := "targetID"
	mockExtension := map[string]interface{}{"strings": "hello world"}

	stage := toInteractionStage(mockStage)
	expected := api.AnalyticsRequestBody{
		Data: api.AnalyticsData{
			Type: mockInstrumentationType,
			Attributes: api.AnalyticsAttributes{
				Interaction: api.Interaction{
					Categories:  &mockCategory,
					Errors:      &[]api.InteractionError{},
					Extension:   &mockExtension,
					Id:          mockInteractionId,
					Results:     toInteractionResults(mockTestSummary),
					Stage:       &stage,
					Status:      string(mockStatus),
					Target:      api.Target{Id: mockTargetId},
					TimestampMs: time.Date(2025, 1, 01, 0, 0, 0, 0, time.UTC).UnixMilli(),
					Type:        mockInteractionType,
				},
				Runtime: &api.Runtime{},
			},
		},
	}

	return expected
}
