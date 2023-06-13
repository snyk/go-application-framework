package networking

import "fmt"

type SnykAppEnvironment struct {
	App                           string
	AppVersion                    string
	Integration                   string
	IntegrationVersion            string
	IntegrationEnvironment        string
	IntegrationEnvironmentVersion string
	Goos                          string
	Goarch                        string
	ProcessName                   string
}

func (s SnykAppEnvironment) String() string { return s.ToUserAgentHeader() }

// ToUserAgentHeader returns a string that can be used as a User-Agent header.
// The string is following this format:
// <app>/<appVer> (<os>;<arch>;<procName>) <integration>/<integrationVersion> (<integrationEnv>/<integrationEnvVersion>)
// Everything other than the app, app version and system information (os/arch/process name) is optional.
// The integration environment is only added if the integration is set.
func (s SnykAppEnvironment) ToUserAgentHeader() string {
	str := fmt.Sprint(
		s.App, "/", s.AppVersion,
		" (", s.Goos, ";", s.Goarch, ";", s.ProcessName, ")",
	)
	if s.Integration != "" {
		str += fmt.Sprint(" ", s.Integration, "/", s.IntegrationVersion)
		if s.IntegrationEnvironment != "" {
			str += fmt.Sprint(" (", s.IntegrationEnvironment, "/", s.IntegrationEnvironmentVersion, ")")
		}
	}

	return str
}
