package bundle

import (
	"fmt"
	"regexp"
)

// authorizationLineRe matches a non-empty Authorization field in the lifted
// log header, e.g. "Authorization:  76f295ce***2e467c27  (type=token)".
var authorizationLineRe = regexp.MustCompile(`(?m)^\s*Authorization:[ \t]*\S`)

// Observations cross-references the gathered signals deterministically and
// returns conclusions the LLM should treat as ground truth. Small local
// models don't reliably connect "header Authorization empty" with "live
// token not configured" on their own; doing the differential here keeps the
// diagnosis on the rails.
func (b *DiagnosticBundle) Observations() []string {
	var observations []string

	logHadAuth := authorizationLineRe.MatchString(b.Header)
	liveAuthOK := b.WhoAmI.Status == SignalOK
	liveToken := !b.Connectivity.Failed && b.Connectivity.TokenPresent
	connectivityKnown := !b.Connectivity.Failed
	endpointsOK := connectivityKnown && len(b.Connectivity.FailureGroups) == 0 && b.Connectivity.HostsTotal > 0
	proxyDetected := connectivityKnown && b.Connectivity.Proxy != "" && b.Connectivity.Proxy != "none detected"
	networkDown := connectivityKnown && b.Connectivity.HostsTotal > 0 && b.Connectivity.HostsOK == 0

	// with the network fully down, every other signal (auth included) fails
	// as a side effect and proves nothing — the network IS the diagnosis
	if networkDown {
		if proxyDetected {
			observations = append(observations,
				fmt.Sprintf("Every Snyk endpoint is unreachable and a proxy is configured (%s). The proxy is the prime suspect: verify it is running and reachable, fix its address, or remove the proxy configuration. Authentication cannot be assessed while the network is down — do NOT suggest `snyk auth` or credential changes.", b.Connectivity.Proxy))
		} else {
			observations = append(observations,
				"Every Snyk endpoint is unreachable from this machine — a network, DNS, or firewall problem. Authentication cannot be assessed while the network is down — do NOT suggest `snyk auth` or credential changes.")
		}
		return observations
	}

	switch {
	case !logHadAuth && !liveAuthOK && connectivityKnown && !liveToken:
		observations = append(observations,
			"No authentication material exists anywhere: the debug log header has an empty Authorization field AND the live check finds no token configured. The user has simply not authenticated. Running `snyk auth` is the complete fix — do not suggest region, proxy, or organization changes, they are not supported by the evidence.")
	case !logHadAuth && liveAuthOK:
		observations = append(observations,
			"The logged run had no Authorization material, but this machine is authenticated now. The failing run likely happened before `snyk auth`, or in a different environment (e.g. CI) where the credentials are not available.")
	case logHadAuth && !liveAuthOK:
		observations = append(observations,
			"Authentication material WAS present during the logged run, yet requests were rejected. A missing token is NOT the problem — consider a token issued for a different region/environment, or an expired/revoked token.")
	case logHadAuth && liveAuthOK:
		observations = append(observations,
			"The live authentication check succeeds on this machine NOW, while the logged run failed with auth material present. Compare the region/environment and credentials of the logged run against the working local configuration (most often: a token from a different region or account).")
	}

	if endpointsOK && !proxyDetected {
		observations = append(observations,
			"All Snyk endpoints are reachable from this machine and no proxy is configured. Do not suggest proxy or network fixes.")
	}
	if connectivityKnown && !endpointsOK && b.Connectivity.HostsTotal > 0 {
		observations = append(observations,
			"Some Snyk endpoints are unreachable from this machine — treat network, proxy, or firewall problems as the primary suspect.")
	}
	if proxyDetected {
		observations = append(observations,
			fmt.Sprintf("A proxy is configured (%s) — consider whether it interferes with the failing requests.", b.Connectivity.Proxy))
	}

	return observations
}
