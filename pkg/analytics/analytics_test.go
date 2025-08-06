package analytics

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/user"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/logging"

	"github.com/stretchr/testify/assert"
)

func Test_Basic(t *testing.T) {
	t.Setenv("CIRCLECI", "true")
	testFields := []string{
		"tfc-token",
		"azurerm-account-key",
		"fetch-tfstate-headers",
		"username",
		"user",
		"password",
		"passw",
		"token",
		"key",
		"secret",
	}

	os := "my-special-OS"
	api := "http://myapi.com"
	org := "MyOrgAs"
	h := http.Header{}
	h.Add("Authorization", "token 4ac534fac6fd6790b7")

	// prepare test data
	args := []string{"test", "--flag", "b=1"}
	for i := range testFields {
		args = append(args, fmt.Sprintf("%s=%s", testFields[i], "secretvalue"))
	}

	commandList := []string{"", "iac capture"}
	for _, cmd := range commandList {
		t.Run(cmd, func(t *testing.T) {
			analytics := newTestAnalytics(t)
			analytics.SetCmdArguments(args)
			analytics.AddError(fmt.Errorf("Something went terrible wrong."))
			analytics.SetVersion("1234567")
			analytics.SetOrg(org)
			analytics.SetApiUrl(api)
			analytics.SetOperatingSystem(os)
			analytics.SetIntegration("Jenkins", "1.2.3.4")
			analytics.SetCommand(cmd)
			analytics.AddHeader(func() http.Header {
				return h.Clone()
			})

			// invoke method under test
			request, err := analytics.GetRequest()

			// compare results
			assert.Nil(t, err)
			assert.NotNil(t, request)
			assert.True(t, analytics.IsCiEnvironment())

			expectedAuthHeader := h["Authorization"]
			actualAuthHeader := request.Header["Authorization"]
			assert.Equal(t, expectedAuthHeader, actualAuthHeader)

			requestUrl := request.URL.String()
			assert.Equal(t, "http://myapi.com/v1/analytics/cli?org=MyOrgAs", requestUrl)
			assert.True(t, strings.Contains(requestUrl, org))

			body, err := io.ReadAll(request.Body)
			assert.Nil(t, err)
			// expect no CLI args to be sent to analytics (CLI-586)
			assert.Equal(t, 0, strings.Count(string(body), logging.SANITIZE_REPLACEMENT_STRING))

			var requestBody dataOutput
			err = json.Unmarshal(body, &requestBody)
			assert.Nil(t, err)

			assert.Equal(t, os, requestBody.Data.OsPlatform)

			if len(cmd) > 0 {
				assert.Equal(t, cmd, requestBody.Data.Command)
			} else {
				assert.Equal(t, "test", requestBody.Data.Command)
			}

			fmt.Println("Request Url: " + requestUrl)
			fmt.Println("Request Body: " + string(body))
		})
	}
}

func Test_SanitizeValuesByKey(t *testing.T) {
	secretNumber := 987654
	secretValues := []string{"mypassword", "123", "#er+aVnqOjnyTtzn-snyk", "Patch", "DogsRule", "CatsDont", "MiceAreOk"}
	expectedNumberOfRedacted := len(secretValues)

	type sanTest struct {
		Password           string `json:"password"`
		JenkinsPassword    string
		PrivateKeySecret   string
		SecretNumber       int
		TotallyPublicValue bool
		Args               []string
	}

	inputStruct := sanTest{
		Password:           secretValues[2],
		JenkinsPassword:    secretValues[0],
		PrivateKeySecret:   secretValues[1],
		SecretNumber:       secretNumber,
		TotallyPublicValue: false,
		Args:               []string{"--some-username=" + secretValues[3], "password=" + secretValues[4], "--something=else", "--mytokenvalue", secretValues[5], "--mykey=" + secretValues[6]},
	}

	// test input
	filter := logging.SENSITIVE_FIELD_NAMES
	input, err := json.Marshal(inputStruct)
	assert.NoError(t, err)

	replacement := logging.SANITIZE_REPLACEMENT_STRING

	fmt.Println("Before: " + string(input))

	// invoke method under test
	output, err := SanitizeValuesByKey(filter, replacement, input)
	assert.NoError(t, err)

	fmt.Println("After: " + string(output))

	assert.NoError(t, err, "Failed to santize!")
	actualNumberOfRedacted := strings.Count(string(output), replacement)
	assert.Equal(t, expectedNumberOfRedacted, actualNumberOfRedacted)

	var outputStruct sanTest
	err = json.Unmarshal(output, &outputStruct)
	assert.NoError(t, err, "Failed to decode json object!")

	// count how often the known secrets are being found in the input and the output
	secretsCountAfter := 0
	secretsCountBefore := 0
	for i := range secretValues {
		secretsCountBefore += strings.Count(string(input), secretValues[i])
		secretsCountAfter += strings.Count(string(output), secretValues[i])
	}
	assert.Equal(t, expectedNumberOfRedacted, secretsCountBefore)
	assert.Equal(t, 0, secretsCountAfter)
}

func Test_SanitizeUsername(t *testing.T) {
	type sanTest struct {
		ErrorLog string
		Other    string
	}

	type input struct {
		userName     string
		domainPrefix string
		homeDir      string
	}

	user, err := testUserCurrent(t)()
	assert.Nil(t, err)

	// runs 3 cases
	// 1. without domain name
	// 2. with domain name
	// 3. user name and path are different
	// 4. current OS values
	replacement := "***"
	inputData := []input{
		{
			userName:     "some.user",
			domainPrefix: "",
			homeDir:      `/Users/some.user/some/Path`,
		},
		{
			userName:     "some.user",
			domainPrefix: "domainName\\",
			homeDir:      `C:\Users\some.user\AppData\Local`,
		},
		{
			userName:     "someuser",
			domainPrefix: "domainName\\",
			homeDir:      `C:\Users\some.user\AppData/Local`,
		},
		{
			userName:     user.Username,
			domainPrefix: "",
			homeDir:      user.HomeDir,
		},
	}

	for i := range inputData {
		simpleUsername := inputData[i].userName
		rawUserName := inputData[i].domainPrefix + inputData[i].userName
		homeDir := inputData[i].homeDir

		inputStruct := sanTest{
			ErrorLog: fmt.Sprintf(`Can't execute %s\path/to/something/file.exe for whatever reason.`, homeDir),
			Other:    fmt.Sprintf("some other value where %s is contained", rawUserName),
		}

		input, err := json.Marshal(inputStruct)
		assert.NoError(t, err)
		fmt.Printf("%d - Before: %s\n", i, string(input))

		// invoke method under test
		output, err := SanitizeUsername(rawUserName, homeDir, replacement, input)

		fmt.Printf("%d - After: %s\n", i, string(output))
		assert.NoError(t, err, "Failed to santize static values!")

		numRedacted := strings.Count(string(output), replacement)
		assert.Equal(t, 2, numRedacted)

		numUsernameInstances := strings.Count(string(output), rawUserName)
		assert.Equal(t, 0, numUsernameInstances)

		numSimpleUsernameInstances := strings.Count(string(output), simpleUsername)
		assert.Equal(t, 0, numSimpleUsernameInstances)

		numHomeDirInstances := strings.Count(string(output), homeDir)
		assert.Equal(t, 0, numHomeDirInstances)

		var outputStruct sanTest
		err = json.Unmarshal(output, &outputStruct)
		assert.NoError(t, err)
	}
}

func newTestAnalytics(t *testing.T) Analytics {
	t.Helper()
	a := New()
	a.(*AnalyticsImpl).userCurrent = testUserCurrent(t) //nolint:errcheck //in this test, the type is clear
	return a
}

func testUserCurrent(t *testing.T) func() (*user.User, error) {
	t.Helper()
	return func() (*user.User, error) {
		return &user.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "test-runner-user",
			Name:     "Test Runner User",
			HomeDir:  t.TempDir(),
		}, nil
	}
}
