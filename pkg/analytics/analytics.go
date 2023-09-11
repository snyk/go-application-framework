package analytics

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/utils"
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
	GetOutputData() *analyticsOutput
	GetRequest() (*http.Request, error)
	Send() (*http.Response, error)
}

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
}

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

var (
	// ciEnvironments is a list of environment variables that indicate a CI environment.
	// it is used to determine if the command is running in a CI environment.
	// if it is, the x-is-ci header is set to true.
	ciEnvironments = []string{
		"SNYK_CI",
		"CI",
		"CONTINUOUS_INTEGRATION",
		"BUILD_ID",
		"BUILD_NUMBER",
		"TEAMCITY_VERSION",
		"TRAVIS",
		"CIRCLECI",
		"JENKINS_URL",
		"HUDSON_URL",
		"bamboo.buildKey",
		"PHPCI",
		"GOCD_SERVER_HOST",
		"BUILDKITE",
		"TF_BUILD",
		"SYSTEM_TEAMFOUNDATIONSERVERURI", // for Azure DevOps Pipelines
	}

	// sensitiveFieldNames is a list of field names that should be sanitized.
	// data sanitization is used to prevent sensitive data from being sent to the analytics server.
	sensitiveFieldNames = []string{
		"headers",
		"user",
		"passw",
		"token",
		"key",
		"secret",
	}
)

const (
	sanitize_replacement_string string = "REDACTED"
	api_endpoint                       = "/v1/analytics/cli"
)

// New creates a new Analytics instance.
func New() Analytics {
	a := &AnalyticsImpl{}
	a.headerFunc = func() http.Header { return http.Header{} }
	a.created = time.Now()
	a.clientFunc = func() *http.Client { return &http.Client{} }
	a.os = runtime.GOOS
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
	result := false

	envMap := utils.ToKeyValueMap(os.Environ(), "=")
	for i := range ciEnvironments {
		if _, ok := envMap[ciEnvironments[i]]; ok {
			result = true
			break
		}
	}

	return result
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
	shasum := sha1.New()
	uuid, _ := uuid.GenerateUUID()
	io.WriteString(shasum, uuid)
	output.Id = fmt.Sprintf("%x", shasum.Sum(nil))

	output.Args = a.args

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
	output.DurationMs = int64(time.Since(a.created).Milliseconds())
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

	outputJson, err = SanitizeValuesByKey(sensitiveFieldNames, sanitize_replacement_string, outputJson)
	if err != nil {
		return nil, err
	}

	user, err := user.Current()
	if err != nil {
		return nil, err
	}
	outputJson, err = SanitizeUsername(user.Username, user.HomeDir, sanitize_replacement_string, outputJson)
	if err != nil {
		return nil, err
	}

	analyticsUrl, _ := url.Parse(a.apiUrl + api_endpoint)
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

var DisabledInFedrampErr = errors.New("analytics are disabled in FedRAMP environments")

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

// SanitizeUsername sanitizes the given content by replacing the given username with the replacement string.
func SanitizeUsername(rawUserName string, userHomeDir string, replacementValue string, content []byte) ([]byte, error) {
	valuesToSanitize := []string{rawUserName, strings.ReplaceAll(userHomeDir, "\\", "\\\\")}

	if strings.Contains(rawUserName, "\\") {
		segments := strings.Split(rawUserName, "\\")
		segmentsLen := len(segments)
		if segmentsLen < 2 {
			// this should never happen because we already checked for the existence of a backslash
			return nil, fmt.Errorf("could not sanitize username")
		} else if segmentsLen == 2 {
			valuesToSanitize = append(valuesToSanitize, segments[1])
		} else {
			// don't recognize this format
			fmt.Println(segments)
			return nil, fmt.Errorf("could not sanitize username - unrecognized format")
		}
	}

	return SanitizeStaticValues(valuesToSanitize, replacementValue, content)
}

func SanitizeStaticValues(valuesToSanitize []string, replacementValue string, content []byte) ([]byte, error) {
	contentStr := string(content)

	for _, valueToReplace := range valuesToSanitize {
		contentStr = strings.ReplaceAll(contentStr, valueToReplace, replacementValue)
	}

	return []byte(contentStr), nil
}
