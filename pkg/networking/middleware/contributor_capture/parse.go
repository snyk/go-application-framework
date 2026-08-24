package contributor_capture

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	projectIDFromURI               = regexp.MustCompile(`/project/([0-9a-fA-F-]{36})(?:/|$)`)
	deeproxyReportCompletePattern  = regexp.MustCompile(`(?i)"status"\s*:\s*"COMPLETE"`)
	deeproxyUploadProjectIDPattern = regexp.MustCompile(`"uploadResult"\s*:\s*\{[^}]*"projectId"\s*:\s*"([0-9a-fA-F-]{36})"`)

	iacShareMetadataKeys = map[string]struct{}{
		"ok":   {},
		"meta": {},
	}
)

type monitorResult struct {
	URI string `json:"uri"`
}

type createTestRequestDoc struct {
	Data struct {
		Attributes struct {
			Configuration struct {
				Output struct {
					Report bool `json:"report"`
				} `json:"output"`
			} `json:"configuration"`
		} `json:"attributes"`
	} `json:"data"`
}

type legacyCreateTestRequestDoc struct {
	Data struct {
		Attributes struct {
			Config *struct {
				PublishReport *bool `json:"publish_report,omitempty"`
				Monitor       *bool `json:"monitor,omitempty"`
			} `json:"config,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

type createTestResponseDoc struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type aiBomUploadRequestDoc struct {
	Data struct {
		Attributes struct {
			UploadRevisionID string `json:"upload_revision_id"`
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

type deeproxyReportBody struct {
	Status       string `json:"status"`
	UploadResult struct {
		ProjectID      string `json:"projectId"`
		ProjectIDSnake string `json:"project_id"`
	} `json:"uploadResult"`
}

// parseCreateTestPublishReport reports whether a CreateTest request body asked for
// publish_report. Supports the Code hidden Test API (configuration.output.report)
// and OSS/IaC/SCA flows (config.publish_report). Native monitor (config.monitor)
// is intentionally excluded.
func parseCreateTestPublishReport(body []byte) bool {
	if parseLegacyCreateTestPublishReport(body) {
		return true
	}
	return parseCodeCreateTestPublishReport(body)
}

func parseLegacyCreateTestPublishReport(body []byte) bool {
	var doc legacyCreateTestRequestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	if doc.Data.Attributes.Config == nil {
		return false
	}
	cfg := doc.Data.Attributes.Config
	if cfg.Monitor != nil && *cfg.Monitor {
		return false
	}
	return cfg.PublishReport != nil && *cfg.PublishReport
}

func parseCodeCreateTestPublishReport(body []byte) bool {
	var doc createTestRequestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	return doc.Data.Attributes.Configuration.Output.Report
}

// parseCreateTestID extracts the test ID from a successful CreateTest response.
func parseCreateTestID(body []byte) string {
	var doc createTestResponseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	return parseUUID(doc.Data.ID)
}

// parseAIBomUploadRevisionID extracts the upload revision ID from an AI-BOM
// upload request body.
func parseAIBomUploadRevisionID(body []byte) string {
	var doc aiBomUploadRequestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	if revisionID := parseUUID(doc.Data.Attributes.UploadRevisionID); revisionID != "" {
		return revisionID
	}
	return ""
}

// parseMonitorProjectID extracts a project ID from a monitor/monitor-dependencies response.
func parseMonitorProjectID(body []byte) string {
	var result monitorResult
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}

	if projectID := projectIDFromMonitorURI(result.URI); projectID != "" {
		return projectID
	}

	return ""
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

// parseIaCShareProjectIDs extracts project IDs from an iac-cli-share-results response.
func parseIaCShareProjectIDs(body []byte) []string {
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

// parseComponentsProjectID extracts the project ID from a successful SAST component in a GetComponents response.
func parseComponentsProjectID(body []byte) string {
	var doc getComponentsResponseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}

	for _, item := range doc.Data {
		if !strings.EqualFold(item.Attributes.Type, "sast") || !item.Attributes.Success {
			continue
		}
		if item.Attributes.Webui == nil || item.Attributes.Webui.ProjectID == nil {
			continue
		}
		if projectID := parseUUID(*item.Attributes.Webui.ProjectID); projectID != "" {
			return projectID
		}
	}
	return ""
}

// parseDeeproxyReportProjectID extracts a project ID from a legacy Code deeproxy
// report response when status is COMPLETE.
func parseDeeproxyReportProjectID(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var doc deeproxyReportBody
	if err := json.Unmarshal(body, &doc); err == nil {
		if !isDeeproxyReportComplete(doc.Status) {
			return ""
		}
		if projectID := parseUUID(firstNonEmpty(doc.UploadResult.ProjectID, doc.UploadResult.ProjectIDSnake)); projectID != "" {
			return projectID
		}
	}

	// Fallback for truncated/overlong bodies where only a prefix was read.
	if !deeproxyReportCompletePattern.Match(body) {
		return ""
	}
	matches := deeproxyUploadProjectIDPattern.FindSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return parseUUID(string(matches[1]))
}

func isDeeproxyReportComplete(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "COMPLETE")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isIaCShareMetadataKey(key string) bool {
	_, ok := iacShareMetadataKeys[strings.ToLower(key)]
	return ok
}
