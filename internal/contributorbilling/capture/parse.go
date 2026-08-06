package capture

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	monitorPathPattern     = regexp.MustCompile(`(?i)^/v1/monitor(?:/|$)`)
	monitorDepsPattern     = regexp.MustCompile(`(?i)^/v1/monitor-dependencies(?:/|$)`)
	iacSharePattern        = regexp.MustCompile(`(?i)^/v1/iac-cli-share-results(?:/|$)`)
	createTestPathPattern  = regexp.MustCompile(`(?i)^/orgs/[0-9a-fA-F-]{36}/tests$`)
	getTestPathPattern     = regexp.MustCompile(`(?i)^/orgs/[0-9a-fA-F-]{36}/tests/([0-9a-fA-F-]{36})$`)
	componentsPathPattern  = regexp.MustCompile(`(?i)^/orgs/[0-9a-fA-F-]{36}/tests/([0-9a-fA-F-]{36})/components$`)
	projectIDFromURI       = regexp.MustCompile(`/project/([0-9a-fA-F-]{36})(?:/|$)`)
	testExecutionCompleted = "completed"

	iacShareMetadataKeys = map[string]struct{}{
		"ok":   {},
		"meta": {},
	}
)

// EndpointKind classifies HTTP traffic for contributor capture routing.
type EndpointKind int

const (
	EndpointNone EndpointKind = iota
	EndpointRegistryMonitor
	EndpointRegistryIaCShare
	EndpointTestCreate
	EndpointTestGet
	EndpointTestComponents
)

type monitorResult struct {
	URI string `json:"uri"`
}

type createTestRequestDoc struct {
	Data struct {
		Attributes struct {
			Config *struct {
				PublishReport *bool `json:"publish_report,omitempty"`
				ScanConfig    *struct {
					Sast json.RawMessage `json:"sast,omitempty"`
				} `json:"scan_config,omitempty"`
			} `json:"config,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

type createTestResponseDoc struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type getTestResponseDoc struct {
	Data struct {
		Attributes struct {
			State *struct {
				Execution *string `json:"execution,omitempty"`
			} `json:"state,omitempty"`
			SubjectLocators []struct {
				Type      string `json:"type"`
				ProjectID string `json:"project_id"`
			} `json:"subject_locators,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

type getComponentsResponseDoc struct {
	Data []struct {
		Attributes struct {
			Type    string `json:"type"`
			Success bool   `json:"success"`
			Webui   *struct {
				ProjectID *string `json:"project_id,omitempty"`
			} `json:"webui,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

// CreateTestRequestMeta holds parsed CreateTest request fields used to register billable tests.
type CreateTestRequestMeta struct {
	PublishReport bool
	Capability    Capability
}

// MatchRequest reports whether method/path targets a product API used for contributor billing capture.
func MatchRequest(method, path string) (EndpointKind, Capability, bool) {
	path = normalizePath(path)
	switch method {
	case http.MethodPut:
		if monitorPathPattern.MatchString(path) || monitorDepsPattern.MatchString(path) {
			return EndpointRegistryMonitor, CapabilityOSS, true
		}
	case http.MethodPost:
		if iacSharePattern.MatchString(path) {
			return EndpointRegistryIaCShare, CapabilityIaC, true
		}
		if createTestPathPattern.MatchString(path) {
			return EndpointTestCreate, "", true
		}
	case http.MethodGet:
		if componentsPathPattern.MatchString(path) {
			return EndpointTestComponents, "", true
		}
		if getTestPathPattern.MatchString(path) {
			return EndpointTestGet, "", true
		}
	}

	return EndpointNone, "", false
}

// ParseCreateTestRequest extracts publish_report and capability from a CreateTest request body.
func ParseCreateTestRequest(body []byte) (CreateTestRequestMeta, bool) {
	var doc createTestRequestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return CreateTestRequestMeta{}, false
	}
	if doc.Data.Attributes.Config == nil || doc.Data.Attributes.Config.PublishReport == nil || !*doc.Data.Attributes.Config.PublishReport {
		return CreateTestRequestMeta{}, false
	}

	capability := CapabilityOSS
	if doc.Data.Attributes.Config.ScanConfig != nil && len(doc.Data.Attributes.Config.ScanConfig.Sast) > 0 {
		capability = CapabilityCode
	}

	return CreateTestRequestMeta{
		PublishReport: true,
		Capability:    capability,
	}, true
}

// ParseCreateTestResponse extracts the test ID from a successful CreateTest response.
func ParseCreateTestResponse(body []byte) string {
	var doc createTestResponseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	return parseUUID(doc.Data.ID)
}

// ParseCaptureRecords extracts billing records from a successful response for the given endpoint.
func ParseCaptureRecords(endpoint EndpointKind, path string, body []byte, testCapability Capability) []Record {
	switch endpoint {
	case EndpointRegistryMonitor:
		return legacyProjectRecords(CapabilityOSS, path, parseMonitorResponse(body))
	case EndpointRegistryIaCShare:
		return legacyProjectRecords(CapabilityIaC, path, parseIaCShareResponse(body))
	case EndpointTestGet:
		testID := testIDFromGetTestPath(path)
		if testID == "" || testCapability == "" {
			return nil
		}
		return parseGetTestResponse(path, body, testCapability)
	case EndpointTestComponents:
		testID := testIDFromComponentsPath(path)
		if testID == "" || testCapability == "" {
			return nil
		}
		return parseGetComponentsResponse(path, body, testCapability)
	default:
		return nil
	}
}

// ParseResponse extracts legacy Registry project IDs from a successful product API response body.
// Deprecated: use ParseCaptureRecords for new call sites.
func ParseResponse(capability Capability, body []byte) []string {
	switch capability {
	case CapabilityOSS:
		return parseMonitorResponse(body)
	case CapabilityIaC:
		return parseIaCShareResponse(body)
	default:
		return nil
	}
}

func legacyProjectRecords(capability Capability, path string, entityIDs []string) []Record {
	if len(entityIDs) == 0 {
		return nil
	}
	out := make([]Record, 0, len(entityIDs))
	for _, entityID := range entityIDs {
		out = append(out, Record{
			Capability:  capability,
			EntityID:    entityID,
			EntityType:  EntityTypeProject,
			RequestPath: path,
		})
	}
	return out
}

func parseGetTestResponse(path string, body []byte, capability Capability) []Record {
	var doc getTestResponseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	if doc.Data.Attributes.State == nil ||
		doc.Data.Attributes.State.Execution == nil ||
		!strings.EqualFold(*doc.Data.Attributes.State.Execution, testExecutionCompleted) {
		return nil
	}

	for _, locator := range doc.Data.Attributes.SubjectLocators {
		if !strings.EqualFold(locator.Type, "project_entity") {
			continue
		}
		if entityID := parseUUID(locator.ProjectID); entityID != "" {
			return []Record{{
				Capability:  capability,
				EntityID:    entityID,
				EntityType:  EntityTypeProject,
				RequestPath: path,
			}}
		}
	}
	return nil
}

func parseGetComponentsResponse(path string, body []byte, capability Capability) []Record {
	var doc getComponentsResponseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}

	for _, item := range doc.Data {
		if !strings.EqualFold(item.Attributes.Type, "sast") || !item.Attributes.Success {
			continue
		}
		if item.Attributes.Webui == nil || item.Attributes.Webui.ProjectID == nil {
			continue
		}
		if entityID := parseUUID(*item.Attributes.Webui.ProjectID); entityID != "" {
			return []Record{{
				Capability:  capability,
				EntityID:    entityID,
				EntityType:  EntityTypeProject,
				RequestPath: path,
			}}
		}
	}
	return nil
}

func parseMonitorResponse(body []byte) []string {
	var result monitorResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	if projectID := projectIDFromMonitorURI(result.URI); projectID != "" {
		return []string{projectID}
	}

	return nil
}

func projectIDFromMonitorURI(uri string) string {
	if uri == "" {
		return ""
	}

	matches := projectIDFromURI.FindStringSubmatch(uri)
	if len(matches) < 2 {
		return ""
	}

	return parseUUID(matches[1])
}

func parseIaCShareResponse(body []byte) []string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var projectIDs []string

	for key, value := range raw {
		if isIaCShareMetadataKey(key) {
			continue
		}

		var projectID string
		if err := json.Unmarshal(value, &projectID); err != nil {
			continue
		}

		projectID = strings.TrimSpace(projectID)
		if projectID = parseUUID(projectID); projectID == "" {
			continue
		}

		if _, exists := seen[projectID]; exists {
			continue
		}
		seen[projectID] = struct{}{}
		projectIDs = append(projectIDs, projectID)
	}

	return projectIDs
}

func testIDFromGetTestPath(path string) string {
	matches := getTestPathPattern.FindStringSubmatch(normalizePath(path))
	if len(matches) < 2 {
		return ""
	}
	return parseUUID(matches[1])
}

func testIDFromComponentsPath(path string) string {
	matches := componentsPathPattern.FindStringSubmatch(normalizePath(path))
	if len(matches) < 2 {
		return ""
	}
	return parseUUID(matches[1])
}

// TestIDFromGetPath returns the test UUID from a GET /orgs/{org}/tests/{test} path.
func TestIDFromGetPath(path string) string {
	return testIDFromGetTestPath(path)
}

// TestIDFromComponentsPath returns the test UUID from a GET .../tests/{test}/components path.
func TestIDFromComponentsPath(path string) string {
	return testIDFromComponentsPath(path)
}

func parseUUID(value string) string {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return parsed.String()
}

func isIaCShareMetadataKey(key string) bool {
	_, ok := iacShareMetadataKeys[strings.ToLower(key)]
	return ok
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}
