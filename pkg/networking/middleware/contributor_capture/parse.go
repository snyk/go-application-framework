package contributor_capture

import (
	"bytes"
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
				Config struct {
					PublishReport bool `json:"publish_report"`
					Monitor       bool `json:"monitor"`
				} `json:"config"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &legacyReq); err == nil {
		cfg := legacyReq.Data.Attributes.Config
		if cfg.Monitor {
			return false
		}
		if cfg.PublishReport {
			return true
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
				Webui   struct {
					ProjectID string `json:"project_id"`
				} `json:"webui"`
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
		if projectID := parseUUID(item.Attributes.Webui.ProjectID); projectID != "" {
			return projectID
		}
	}
	return ""
}

// parseDeeproxyReportProjectID extracts a project ID from a legacy Code deeproxy
// report response. It handles truncated JSON, as long as the project ID and the
// surrounding object are present.
func parseDeeproxyReportProjectID(body []byte) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return ""
	}

	for {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey {
			return ""
		}

		if key != "uploadResult" {
			var skipped json.RawMessage
			if err := dec.Decode(&skipped); err != nil {
				return ""
			}
			continue
		}

		var uploadResult struct {
			ProjectID string `json:"projectId"`
		}
		if err := dec.Decode(&uploadResult); err != nil {
			return ""
		}
		return parseUUID(uploadResult.ProjectID)
	}
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
