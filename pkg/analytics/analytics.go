package analytics

import (
	"bytes"

	"github.com/snyk/go-application-framework/pkg/logging"

	//nolint:gosec // insecure sha1 used for legacy identifier
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/metrics"
	utils2 "github.com/snyk/go-application-framework/internal/utils"
)

// Analytics is an interface for managing analytics.
type Analytics interface {
	SetCmdArguments(args []string)
	SetOrg(org string)
	SetVersion(version string)
	SetApiUrl(apiUrl string)
	SetIntegration(name string, version string)
	SetCommand(command string)
	SetOperatingSystem(os string)
	AddError(err error)
	AddHeader(headerFunc func() http.Header)
	SetClient(clientFunc func() *http.Client)
	IsCiEnvironment() bool
	GetRequest() (*http.Request, error)
	Send() (*http.Response, error)
	GetInstrumentation() InstrumentationCollector
	AddExtensionIntegerValue(key string, value int)
	AddExtensionStringValue(key string, value string)
	AddExtensionBoolValue(key string, value bool)
}

// Compile-time check that Analytics satisfies metrics.Recorder.
var _ metrics.Recorder = (Analytics)(nil)

// AnalyticsImpl is the default implementation of the Analytics interface.
type AnalyticsImpl struct {
	clientFunc func() *http.Client
	headerFunc func() http.Header
	apiUrl     string

	org                string
	version            string
	created            time.Time
	args               []string
	errorList          []error
	integrationName    string
	integrationVersion string
	os                 string
	command            string
	instrumentor       InstrumentationCollector

	userCurrent func() (*user.User, error)
}

var _ Analytics = (*AnalyticsImpl)(nil)

// metadataOutput defines the metadataOutput payload.
type metadataOutput struct {
	ErrorMessage string `json:"error-message,omitempty"`
	ErrorCode    string `json:"error-code,omitempty"`
}

// metricsOutput defines the metricsOutput payload.
type metricsOutput struct {
}

// analyticsOutput defines the analyticsOutput payload.
type analyticsOutput struct {
	Command                       string         `json:"command"`
	Args                          []string       `json:"args"`
	OsPlatform                    string         `json:"osPlatform"`
	OsArch                        string         `json:"osArch"`
	Os                            string         `json:"os"`
	OsRelease                     string         `json:"osRelease"`
	Metadata                      metadataOutput `json:"metadata"`
	Id                            string         `json:"id"`
	Version                       string         `json:"version"`
	DurationMs                    int64          `json:"durationMs"`
	Metrics                       metricsOutput  `json:"metrics"`
	Ci                            bool           `json:"ci"`
	IntegrationName               string         `json:"integrationName"`
	IntegrationVersion            string         `json:"integrationVersion"`
	IntegrationEnvironment        string         `json:"integrationEnvironment"`
	IntegrationEnvironmentVersion string         `json:"integrationEnvironmentVersion"`
	NodeVersion                   string         `json:"nodeVersion"`
	Standalone                    bool           `json:"standalone"`
}

// dataOutput defines the dataOutput payload.
type dataOutput struct {
	Data analyticsOutput `json:"data"`
}

const (
	apiEndpoint string = "/v1/analytics/cli"
)

// New creates a new Analytics instance.
func New() Analytics {
	a := &AnalyticsImpl{
		userCurrent: user.Current,
	}
	a.headerFunc = func() http.Header { return http.Header{} }
	a.created = time.Now()
	a.clientFunc = func() *http.Client { return &http.Client{} }
	a.os = runtime.GOOS
	a.instrumentor = NewInstrumentationCollector()
	a.instrumentor.SetTimestamp(a.created)
	return a
}

// SetCmdArguments sets the command arguments.
func (a *AnalyticsImpl) SetCmdArguments(args []string) {
	a.args = args
}

// SetOrg sets the organization.
func (a *AnalyticsImpl) SetOrg(org string) {
	a.org = org
}

// SetVersion sets the version.
func (a *AnalyticsImpl) SetVersion(version string) {
	a.version = version
}

// SetApiUrl sets the API URL.
func (a *AnalyticsImpl) SetApiUrl(apiUrl string) {
	a.apiUrl = apiUrl
}

// SetIntegration sets the integration name and version.
func (a *AnalyticsImpl) SetIntegration(name string, version string) {
	a.integrationName = name
	a.integrationVersion = version
}

func (a *AnalyticsImpl) SetCommand(command string) {
	a.command = command
}

func (a *AnalyticsImpl) SetOperatingSystem(os string) {
	a.os = os
}

// AddError adds an error to the error list.
func (a *AnalyticsImpl) AddError(err error) {
	a.errorList = append(a.errorList, err)

	if a.instrumentor != nil {
		a.instrumentor.AddError(err)
	}
}

func (a *AnalyticsImpl) AddExtensionIntegerValue(key string, value int) {
	if a.instrumentor != nil {
		a.instrumentor.AddExtension(key, value)
	}
}

func (a *AnalyticsImpl) AddExtensionStringValue(key string, value string) {
	if a.instrumentor != nil {
		a.instrumentor.AddExtension(key, value)
	}
}

func (a *AnalyticsImpl) AddExtensionBoolValue(key string, value bool) {
	if a.instrumentor != nil {
		a.instrumentor.AddExtension(key, value)
	}
}

// AddHeader adds a header to the request.
func (a *AnalyticsImpl) AddHeader(headerFunc func() http.Header) {
	a.headerFunc = headerFunc
}

// SetClient sets the HTTP client.
func (a *AnalyticsImpl) SetClient(clientFunc func() *http.Client) {
	a.clientFunc = clientFunc
}

// IsCiEnvironment returns true if the command is running in a CI environment.
func (a *AnalyticsImpl) IsCiEnvironment() bool {
	return utils2.IsCiEnvironment()
}

// GetOutputData returns the analyticsOutput data.
func (a *AnalyticsImpl) GetOutputData() *analyticsOutput {
	output := &analyticsOutput{}

	errorCount := len(a.errorList)
	if errorCount > 0 {
		lastError := a.errorList[errorCount-1]
		output.Metadata = metadataOutput{
			ErrorMessage: lastError.Error(),
		}
	}

	// deepcode ignore InsecureHash: It is just being used to generate an id, without any security concerns
	//nolint:gosec // sha1 only used to generate an id
	shasum := sha1.New()
	//nolint:errcheck // breaking api change needed to fix this
	uuid, _ := uuid.GenerateUUID()
	//nolint:errcheck // breaking api change needed to fix this
	io.WriteString(shasum, uuid)
	output.Id = fmt.Sprintf("%x", shasum.Sum(nil))

	// CLI-586 - stop sending CLI args to analytics
	output.Args = []string{}

	if len(a.command) > 0 {
		output.Command = a.command
	} else if len(a.args) > 0 {
		output.Command = a.args[0]
	}

	output.OsPlatform = a.os
	output.OsArch = runtime.GOARCH
	output.Version = a.version
	output.NodeVersion = runtime.Version()
	output.Ci = a.IsCiEnvironment()
	output.IntegrationName = a.integrationName
	output.IntegrationVersion = a.integrationVersion
	output.DurationMs = time.Since(a.created).Milliseconds()
	output.Standalone = true // standalone means binary deployment, which is always true for go applications.

	return output
}

// GetRequest returns the HTTP request.
func (a *AnalyticsImpl) GetRequest() (*http.Request, error) {
	if !a.isEnabled() {
		return nil, DisabledInFedrampErr
	}
	output := a.GetOutputData()

	outputJson, err := json.Marshal(dataOutput{Data: *output})
	if err != nil {
		return nil, err
	}

	outputJson, err = SanitizeValuesByKey(logging.SENSITIVE_FIELD_NAMES, logging.SANITIZE_REPLACEMENT_STRING, outputJson)
	if err != nil {
		return nil, err
	}

	user, err := a.userCurrent()
	if err != nil {
		return nil, err
	}
	outputJson, err = SanitizeUsername(user.Username, user.HomeDir, logging.SANITIZE_REPLACEMENT_STRING, outputJson)
	if err != nil {
		return nil, err
	}

	analyticsUrl, err := url.Parse(a.apiUrl + apiEndpoint)
	if err != nil {
		return nil, err
	}
	if len(a.org) > 0 {
		query := url.Values{}
		query.Add("org", a.org)
		analyticsUrl.RawQuery = query.Encode()
	}

	body := bytes.NewReader(outputJson)
	request, err := http.NewRequest(http.MethodPost, analyticsUrl.String(), body)
	if err != nil {
		return nil, err
	}

	if a.headerFunc != nil {
		request.Header = a.headerFunc()
	}

	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	return request, err
}

func (a *AnalyticsImpl) Send() (*http.Response, error) {
	if !a.isEnabled() {
		return nil, DisabledInFedrampErr
	}
	request, err := a.GetRequest()
	if err != nil {
		return nil, err
	}

	client := a.clientFunc()
	response, err := client.Do(request)

	return response, err
}

func (a *AnalyticsImpl) isEnabled() bool {
	return !api.IsFedramp(a.apiUrl)
}

func (a *AnalyticsImpl) GetInstrumentation() InstrumentationCollector {
	return a.instrumentor
}

func (a *AnalyticsImpl) SetInstrumentation(ic InstrumentationCollector) {
	a.instrumentor = ic
}

var DisabledInFedrampErr = errors.New("analytics are disabled in FedRAMP environments") //nolint:errname // breaking API change

// This method sanitizes the given content by searching for key-value mappings. It thereby replaces all keys defined in keysToFilter by the replacement string
// Supported patterns are:
// * key : "value"
// * key = "value"
// * key = value
// * key "value"

func SanitizeValuesByKey(keysToFilter []string, replacementValue string, content []byte) ([]byte, error) {
	for i := range keysToFilter {
		filter := keysToFilter[i]
		r, err := regexp.Compile("(?i)([\"']?\\w*" + filter + "\\w*\"?)(((\\s?[:]\\s?[\"'])[^\n\"']*([\"']))|((\\s?[= ,]\\s?[\"']?)[^\n\"']*([\"']?)))")
		if err != nil {
			return nil, err
		}

		content = r.ReplaceAll(content, []byte("${1}${4}${7}"+replacementValue+"${5}${8}"))
	}
	return content, nil
}

// SanitizeUsername sanitizes the given content by replacing the given username with the
// replacement string.
//
// The username matches on a word boundary, via the same logging.UsernameScrubPattern the scrub
// dictionary compiles, so the two paths can't drift apart. The home directory is a full path
// rather than a bare word, so it stays a plain substring match.
//
// When content is valid JSON the replacement runs over string leaf values only. Object keys, and
// numbers, booleans and null, pass through untouched. Replacing the username as a plain literal
// across marshaled JSON used to rewrite keys too, so on a host running as user `app` the key
// `gaf.app.defaultfunc.organization.lookup` arrived as `gaf.***.defaultfunc.organization.lookup`,
// minting a fresh field path per user and fragmenting the analytics facet space (CLI-1819).
//
// Content that nothing matches is returned byte for byte, so the overwhelmingly common payload --
// one carrying no username at all -- keeps its original key order and its original escaping. A
// payload that does get redacted is re-encoded, and re-encoding a JSON object sorts its keys;
// that's accepted, since JSON object members are unordered by definition and every consumer of
// this payload parses it rather than pattern-matching the bytes.
func SanitizeUsername(rawUserName string, userHomeDir string, replacementValue string, content []byte) ([]byte, error) {
	if rawUserName == "" && userHomeDir == "" {
		return content, nil
	}

	userNames := []string{rawUserName}

	if strings.Contains(rawUserName, "\\") {
		segments := strings.Split(rawUserName, "\\")
		if len(segments) != 2 {
			// don't recognize this format
			return nil, fmt.Errorf("could not sanitize username - unrecognized format")
		}
		userNames = append(userNames, segments[1])
	}

	patterns := make([]*regexp.Regexp, 0, len(userNames))
	for _, userName := range userNames {
		if userName == "" {
			continue
		}
		pattern, err := regexp.Compile(logging.UsernameScrubPattern(userName))
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}

	redacted := false
	redact := func(value string) string {
		result := value
		for _, pattern := range patterns {
			result = pattern.ReplaceAllLiteralString(result, replacementValue)
		}
		if userHomeDir != "" {
			result = strings.ReplaceAll(result, userHomeDir, replacementValue)
		}
		if result != value {
			redacted = true
		}
		return result
	}

	if !json.Valid(content) {
		return []byte(redact(string(content))), nil
	}

	// UseNumber so a number survives the round trip verbatim instead of being reformatted through
	// float64.
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()

	var document interface{}
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}

	switch document.(type) {
	case string, map[string]interface{}, []interface{}:
		document = redactStringLeaves(document, redact)
	default:
		// A document that is a bare number, boolean or null holds no string leaf to walk, but the
		// whole document is still a value rather than a key, so a username standing there is
		// redacted like any other. The result is text and goes out quoted, the same shape
		// SanitizeStaticValues produces when it replaces a bare JSON value.
		document = redact(string(bytes.TrimSpace(content)))
	}

	if !redacted {
		return content, nil
	}

	return marshalWithoutHTMLEscaping(document)
}

// marshalWithoutHTMLEscaping marshals document with json.Marshal's HTML escaping switched off.
// SanitizeUsername is a redaction pass over a payload someone else built, so turning a `<`, `>` or
// `&` that it was never asked to touch into `\u003c`, `\u003e` or `\u0026` would be a wire change
// nobody requested.
func marshalWithoutHTMLEscaping(document interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	// Encode terminates every value with a newline; the callers here want the bare value.
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// SanitizeStaticValues replaces every occurrence of each valuesToSanitize entry in content with
// replacementValue. Replacement is JSON-aware (see logging.RedactStaticTerm) only when content is
// itself valid JSON: the bare-value quoting that keeps a redacted JSON payload parseable would
// otherwise inject stray quotes into a plain-text snippet -- something an exported function has to
// tolerate, since it can't assume every caller passes valid JSON.
func SanitizeStaticValues(valuesToSanitize []string, replacementValue string, content []byte) ([]byte, error) {
	contentStr := string(content)
	jsonAware := json.Valid(content)

	for _, valueToReplace := range valuesToSanitize {
		if valueToReplace == "" {
			continue // strings.ReplaceAll inserts replacementValue between every rune for an empty old string
		}
		if jsonAware {
			contentStr = logging.RedactStaticTerm(contentStr, valueToReplace, replacementValue)
		} else {
			contentStr = strings.ReplaceAll(contentStr, valueToReplace, replacementValue)
		}
	}

	return []byte(contentStr), nil
}
