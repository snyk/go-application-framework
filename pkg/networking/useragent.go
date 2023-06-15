package networking

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type UserAgentOptions func(ua *UserAgentInfo)

type UserAgentInfo struct {
	App                           string
	AppVersion                    string
	Integration                   string
	IntegrationVersion            string
	IntegrationEnvironment        string
	IntegrationEnvironmentVersion string
	OS                            string
	Arch                          string
	ProcessName                   string
}

func UserAgentFromConfig(config configuration.Configuration, app string, appVersion string) UserAgentInfo {
	ua := UserAgent(UaWithConfig(config), UaWithApplication(app, appVersion))
	return ua
}

func UaWithConfig(config configuration.Configuration) UserAgentOptions {
	result := func(ua *UserAgentInfo) {
		ua.Integration = config.GetString(configuration.INTEGRATION_NAME)
		ua.IntegrationVersion = config.GetString(configuration.INTEGRATION_VERSION)
		ua.IntegrationEnvironment = config.GetString(configuration.INTEGRATION_ENVIRONMENT)
		ua.IntegrationEnvironmentVersion = config.GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION)
	}
	return result
}

func UaWithApplication(app string, appVersion string) UserAgentOptions {
	result := func(ua *UserAgentInfo) {
		ua.App = app
		ua.AppVersion = appVersion
	}
	return result
}

func UaWithOS(osName string) UserAgentOptions {
	result := func(ua *UserAgentInfo) {
		ua.OS = osName
	}
	return result
}

func UserAgent(opts ...UserAgentOptions) UserAgentInfo {
	processName, _ := os.Executable()
	ua := UserAgentInfo{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		ProcessName: filepath.Base(processName),
	}

	for _, opt := range opts {
		opt(&ua)
	}

	return ua
}

// ToUserAgentHeader returns a string that can be used as a User-Agent header.
// The string is following this format:
// <app>/<appVer> (<os>;<arch>;<procName>) <integration>/<integrationVersion> (<integrationEnv>/<integrationEnvVersion>)
// Everything other than the app, app version and system information (os/arch/process name) is optional.
// The integration environment is only added if the integration is set.
func (s UserAgentInfo) String() string {
	str := fmt.Sprint(
		s.App, "/", s.AppVersion,
		" (", s.OS, ";", s.Arch, ";", s.ProcessName, ")",
	)
	if s.Integration != "" {
		str += fmt.Sprint(" ", s.Integration, "/", s.IntegrationVersion)
		if s.IntegrationEnvironment != "" {
			str += fmt.Sprint(" (", s.IntegrationEnvironment, "/", s.IntegrationEnvironmentVersion, ")")
		}
	}

	return str
}
