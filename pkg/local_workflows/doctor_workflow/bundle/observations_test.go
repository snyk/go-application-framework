package bundle

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func observationsFor(headerAuth string, authOK bool, tokenPresent bool, failedHosts int) []string {
	header := "Version: 1.0\nAuthorization:" + headerAuth + "\nChecks:"
	status := SignalFailed
	if authOK {
		status = SignalOK
	}
	b := &DiagnosticBundle{
		Header: header,
		WhoAmI: Signal{Status: status},
		Connectivity: ConnectivitySummary{
			HostsOK:      16 - failedHosts,
			HostsTotal:   16,
			TokenPresent: tokenPresent,
			Proxy:        "none detected",
		},
	}
	if failedHosts > 0 {
		b.Connectivity.FailureGroups = []HostFailureGroup{{Status: "BLOCKED", Hosts: make([]string, failedHosts)}}
	}
	return b.Observations()
}

func Test_Observations_neverAuthenticated(t *testing.T) {
	obs := observationsFor("", false, false, 0)

	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0], "has simply not authenticated")
	assert.Contains(t, obs[0], "`snyk auth` is the complete fix")
	// healthy network must explicitly rule out proxy fixes
	assert.Contains(t, strings.Join(obs, " "), "Do not suggest proxy or network fixes")
}

func Test_Observations_tokenPresentButRejected(t *testing.T) {
	obs := observationsFor("  76f295ce***  (type=token)", false, true, 0)

	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0], "A missing token is NOT the problem")
}

func Test_Observations_logFailedButLiveWorks(t *testing.T) {
	obs := observationsFor("  76f295ce***  (type=token)", true, true, 0)

	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0], "succeeds on this machine NOW")
}

func Test_Observations_loggedRunLackedCredentials(t *testing.T) {
	obs := observationsFor("", true, true, 0)

	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0], "logged run had no Authorization material")
}

func Test_Observations_someEndpointsUnreachable(t *testing.T) {
	obs := observationsFor("", false, false, 4)

	assert.Contains(t, strings.Join(obs, " "), "network, proxy, or firewall problems as the primary suspect")
}

func Test_Observations_networkFullyDown_dominatesAuth(t *testing.T) {
	obs := observationsFor("", false, false, 16)

	joined := strings.Join(obs, " ")
	assert.Contains(t, joined, "network, DNS, or firewall problem")
	assert.Contains(t, joined, "do NOT suggest `snyk auth`")
	// auth status is unknowable offline; the differential must stay silent
	assert.NotContains(t, joined, "simply not authenticated")
	assert.NotContains(t, joined, "`snyk auth` is the complete fix")
}

func Test_Observations_networkFullyDownWithProxy_blamesProxy(t *testing.T) {
	b := &DiagnosticBundle{
		Header: "Authorization:",
		WhoAmI: Signal{Status: SignalFailed},
		Connectivity: ConnectivitySummary{
			HostsOK: 0, HostsTotal: 16,
			FailureGroups: []HostFailureGroup{{Status: "BLOCKED", Hosts: make([]string, 16)}},
			Proxy:         "HTTPS_PROXY=http://127.0.0.1:3128",
		},
	}
	obs := strings.Join(b.Observations(), " ")

	assert.Contains(t, obs, "proxy is the prime suspect")
	assert.Contains(t, obs, "HTTPS_PROXY=http://127.0.0.1:3128")
	assert.NotContains(t, obs, "simply not authenticated")
}

func Test_Observations_proxyDetected(t *testing.T) {
	b := &DiagnosticBundle{
		Header: "Authorization:",
		WhoAmI: Signal{Status: SignalFailed},
		Connectivity: ConnectivitySummary{
			HostsOK: 16, HostsTotal: 16, Proxy: "HTTPS_PROXY=http://proxy:8080",
		},
	}
	obs := strings.Join(b.Observations(), " ")

	assert.Contains(t, obs, "A proxy is configured (HTTPS_PROXY=http://proxy:8080)")
	assert.NotContains(t, obs, "Do not suggest proxy")
}

func Test_Observations_connectivityCheckFailed_noNetworkClaims(t *testing.T) {
	b := &DiagnosticBundle{
		Header:       "Authorization:",
		WhoAmI:       Signal{Status: SignalFailed},
		Connectivity: ConnectivitySummary{Failed: true, FailureText: "timeout"},
	}
	obs := strings.Join(b.Observations(), " ")

	// with no connectivity data, neither "all reachable" nor "unreachable"
	// claims can be made, and "never authenticated" can't be confirmed
	assert.NotContains(t, obs, "Do not suggest proxy")
	assert.NotContains(t, obs, "primary suspect")
	assert.NotContains(t, obs, "simply not authenticated")
}
