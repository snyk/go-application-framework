package connectivity

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	connectivitycheck "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"
	checkconnectivity "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension/connectivity"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// noProgressConfigKey suppresses the connectivity-check progress bar when doctor
// invokes the workflow in the background while other checks run.
const noProgressConfigKey = "no-progress"

type connectivitySummary struct {
	Failed      bool
	FailureText string

	Proxy         string
	HostsOK       int
	HostsTotal    int
	FailureGroups []hostFailureGroup
	TokenPresent  bool
	OrgCount      int
	Organizations []string
	Warnings      []string
}

type hostFailureGroup struct {
	Status string
	Hosts  []string
}

type connectivityStatus struct {
	Summary connectivitySummary
}

type connectivityResult struct {
	ProxyConfig checkconnectivity.ProxyConfig `json:"proxyConfig"`
	HostResults []struct {
		Host   string                             `json:"host"`
		Status checkconnectivity.ConnectionStatus `json:"status"`
	} `json:"hostResults"`
	TODOs         []checkconnectivity.TODO         `json:"todos"`
	Organizations []checkconnectivity.Organization `json:"organizations"`
	TokenPresent  bool                             `json:"tokenPresent"`
}

// AsyncCheck runs Check in the background. Call Wait for the result.
type AsyncCheck struct {
	done chan connectivityStatus
}

// StartAsync begins the connectivity check without blocking the caller.
func StartAsync(invocationCtx workflow.InvocationContext) *AsyncCheck {
	async := &AsyncCheck{done: make(chan connectivityStatus, 1)}
	go func() {
		async.done <- Check(invocationCtx)
	}()
	return async
}

// Wait blocks until the background connectivity check completes.
func (a *AsyncCheck) Wait() connectivityStatus {
	return <-a.done
}

func connectivityConfig(base configuration.Configuration) configuration.Configuration {
	config := base.Clone()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	config.Set("json", true)
	config.Set("timeout", 10)
	config.Set("max-org-count", 100)
	config.Set(noProgressConfigKey, true)
	return config
}

func Check(invocationCtx workflow.InvocationContext) connectivityStatus {
	data, err := invocationCtx.GetEngine().InvokeWithConfig(
		connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK,
		connectivityConfig(invocationCtx.GetConfiguration()),
	)
	if err != nil {
		return connectivityStatus{Summary: connectivitySummary{Failed: true, FailureText: err.Error()}}
	}

	payload, ok := firstPayloadString(data)
	if !ok {
		return connectivityStatus{Summary: connectivitySummary{Failed: true, FailureText: "connectivity check returned no usable result"}}
	}

	var result connectivityResult
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		return connectivityStatus{Summary: connectivitySummary{
			Failed:      true,
			FailureText: fmt.Sprintf("could not decode connectivity result: %s", err),
		}}
	}

	return connectivityStatus{Summary: summarizeConnectivity(result)}
}

func summarizeConnectivity(result connectivityResult) connectivitySummary {
	summary := connectivitySummary{
		Proxy:        "none detected",
		HostsTotal:   len(result.HostResults),
		TokenPresent: result.TokenPresent,
		OrgCount:     len(result.Organizations),
	}

	if result.ProxyConfig.Detected {
		summary.Proxy = fmt.Sprintf("%s=%s", result.ProxyConfig.Variable, result.ProxyConfig.URL)
		if result.ProxyConfig.NoProxy != "" {
			summary.Proxy += fmt.Sprintf("  (NO_PROXY=%s)", result.ProxyConfig.NoProxy)
		}
	}

	failureIndex := map[string]int{}
	for _, host := range result.HostResults {
		switch host.Status {
		case checkconnectivity.StatusOK, checkconnectivity.StatusReachable, checkconnectivity.StatusProxyAuthSupported:
			summary.HostsOK++
		default:
			status := host.Status.String()
			i, ok := failureIndex[status]
			if !ok {
				summary.FailureGroups = append(summary.FailureGroups, hostFailureGroup{Status: status})
				i = len(summary.FailureGroups) - 1
				failureIndex[status] = i
			}
			summary.FailureGroups[i].Hosts = append(summary.FailureGroups[i].Hosts, host.Host)
		}
	}

	summary.Organizations = describeOrganizations(result.Organizations, 10)

	for _, todo := range result.TODOs {
		// Host failures are already summarized in FailureGroups; per-host TodoFail
		// messages repeat the same detail (often including raw Get/url errors).
		if todo.Level == checkconnectivity.TodoInfo || todo.Level == checkconnectivity.TodoWarn {
			summary.Warnings = append(summary.Warnings, todo.Message)
		}
	}
	return summary
}

func describeOrganizations(orgs []checkconnectivity.Organization, limit int) []string {
	var lines []string
	for _, org := range orgs {
		line := org.Slug
		if org.IsDefault {
			line += " (default)"
			lines = append([]string{line}, lines...)
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) > limit {
		lines = append(lines[:limit], fmt.Sprintf("+%d more", len(lines)-limit))
	}
	return lines
}

func firstPayloadString(data []workflow.Data) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	switch payload := data[0].GetPayload().(type) {
	case []byte:
		return string(payload), true
	case string:
		return payload, true
	default:
		return "", false
	}
}

func (c connectivityStatus) Findings() []diagnosis.Finding {
	if c.Summary.Failed {
		return []diagnosis.Finding{{
			Source:   diagnosis.SourceConnectivity,
			Kind:     "connectivity",
			Severity: diagnosis.SeverityError,
			Message:  "Failed to run connectivity check",
			Details:  []string{c.Summary.FailureText},
		}}
	}

	token := "not configured"
	if c.Summary.TokenPresent {
		token = "configured"
	}

	fields := map[string]string{
		"proxy": c.Summary.Proxy,
		"token": token,
		"hosts": fmt.Sprintf("%d/%d reachable", c.Summary.HostsOK, c.Summary.HostsTotal),
	}

	var details []string
	if c.Summary.OrgCount > 0 {
		details = append(details, fmt.Sprintf("Organizations: %d", c.Summary.OrgCount))
		details = append(details, c.Summary.Organizations...)
	}
	for _, group := range c.Summary.FailureGroups {
		details = append(details, fmt.Sprintf("%s: %s", group.Status, joinHosts(group.Hosts)))
	}
	details = append(details, c.Summary.Warnings...)

	return []diagnosis.Finding{{
		Source:   diagnosis.SourceConnectivity,
		Kind:     "connectivity",
		Severity: diagnosis.SeverityInfo,
		Message:  fmt.Sprintf("Hosts: %d/%d reachable", c.Summary.HostsOK, c.Summary.HostsTotal),
		Fields:   fields,
		Details:  details,
	}}
}

func joinHosts(hosts []string) string {
	return strings.Join(hosts, ", ")
}
