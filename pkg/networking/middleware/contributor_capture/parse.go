package contributor_capture

import (
	"encoding/json"
	"strings"
)

// parseCreateTestPublishReport reports whether a CreateTest request body asked for
// publish_report. Supports the Code hidden Test API (configuration.output.report)
// and OSS/IaC/SCA flows (config.publish_report). Native monitor (config.monitor)
// is intentionally excluded.
func parseCreateTestPublishReport(body []byte) bool {
	// Try legacy format first (OSS/IaC/SCA)
	var legacyReq struct {
		Data struct {
			Attributes struct {
				Config *struct {
					PublishReport *bool `json:"publish_report,omitempty"`
					Monitor       *bool `json:"monitor,omitempty"`
				} `json:"config,omitempty"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &legacyReq); err == nil {
		if legacyReq.Data.Attributes.Config != nil {
			cfg := legacyReq.Data.Attributes.Config
			if cfg.Monitor != nil && *cfg.Monitor {
				return false
			}
			if cfg.PublishReport != nil && *cfg.PublishReport {
				return true
			}
		}
	}

	// Try new format (Code API)
	var newReq struct {
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
	if err := json.Unmarshal(body, &newReq); err == nil {
		return newReq.Data.Attributes.Configuration.Output.Report
	}

	return false
}

// parseCreateTestID extracts the test ID from a successful CreateTest response.
func parseCreateTestID(body []byte) string {
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	return parseUUID(resp.Data.ID)
}

// parseAIBomUploadRevisionID extracts the upload revision ID from an AI-BOM upload request body.
func parseAIBomUploadRevisionID(body []byte) string {
	var req struct {
		Data struct {
			Attributes struct {
				UploadRevisionID string `json:"upload_revision_id"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return parseUUID(req.Data.Attributes.UploadRevisionID)
}

// parseMonitorProjectID extracts a project ID from a monitor/monitor-dependencies response.
func parseMonitorProjectID(body []byte) string {
	var resp struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	return projectIDFromMonitorURI(resp.URI)
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
		// Skip metadata keys
		if _, isMetadata := map[string]struct{}{"ok": {}, "meta": {}}[strings.ToLower(key)]; isMetadata {
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
	var resp struct {
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
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	for _, item := range resp.Data {
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

	// Try full JSON unmarshal first
	var resp struct {
		Status       string `json:"status"`
		UploadResult struct {
			ProjectID      string `json:"projectId"`
			ProjectIDSnake string `json:"project_id"`
		} `json:"uploadResult"`
	}
	if err := json.Unmarshal(body, &resp); err == nil {
		if !strings.EqualFold(strings.TrimSpace(resp.Status), "COMPLETE") {
			return ""
		}
		// Try projectId first, fall back to project_id
		if pid := resp.UploadResult.ProjectID; strings.TrimSpace(pid) != "" {
			return parseUUID(pid)
		}
		if pid := resp.UploadResult.ProjectIDSnake; strings.TrimSpace(pid) != "" {
			return parseUUID(pid)
		}
	}

	// Fallback for truncated bodies where JSON unmarshal failed
	return extractDeeproxyProjectIDFromTruncated(body)
}

// projectIDFromMonitorURI extracts a project ID from a monitor API response URI.
// Handles URIs like https://app.snyk.io/org/{org}/project/{uuid}/history/{id}.
func projectIDFromMonitorURI(uri string) string {
	if uri == "" {
		return ""
	}

	const projectPrefix = "/project/"
	idx := strings.Index(uri, projectPrefix)
	if idx < 0 {
		return ""
	}

	uuidStart := idx + len(projectPrefix)
	if uuidStart+36 > len(uri) {
		return ""
	}

	// Verify UUID is followed by / or end of string
	uuidCandidate := uri[uuidStart : uuidStart+36]
	if uuidStart+36 < len(uri) && uri[uuidStart+36] != '/' {
		return ""
	}

	return parseUUID(uuidCandidate)
}

// extractDeeproxyProjectIDFromTruncated extracts project ID from truncated/malformed JSON.
func extractDeeproxyProjectIDFromTruncated(body []byte) string {
	s := string(body)

	// Check for COMPLETE status
	if !strings.Contains(strings.ToUpper(s), `"COMPLETE"`) {
		return ""
	}

	// Find uploadResult and extract projectId/project_id
	uploadIdx := strings.Index(s, `"uploadResult"`)
	if uploadIdx < 0 {
		return ""
	}

	searchFrom := uploadIdx
	for _, fieldName := range []string{`"projectId"`, `"project_id"`} {
		fieldIdx := strings.Index(s[searchFrom:], fieldName)
		if fieldIdx < 0 {
			continue
		}

		// Find the value after the field
		valueStart := searchFrom + fieldIdx + len(fieldName)
		colonIdx := strings.Index(s[valueStart:], ":")
		if colonIdx < 0 || colonIdx > 10 {
			continue
		}

		quoteIdx := strings.Index(s[valueStart+colonIdx:], `"`)
		if quoteIdx < 0 || quoteIdx > 5 {
			continue
		}

		uuidStart := valueStart + colonIdx + quoteIdx + 1
		if uuidStart+36 > len(s) || s[uuidStart+36] != '"' {
			continue
		}

		if projectID := parseUUID(s[uuidStart : uuidStart+36]); projectID != "" {
			return projectID
		}
	}

	return ""
}
