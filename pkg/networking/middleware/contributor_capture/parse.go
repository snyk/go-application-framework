package contributor_capture

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
)

// responseExtractorFor returns the extractor for the entity a response of this
// kind carries, or nil for a kind whose entity comes from the request.
func responseExtractorFor(kind endpointKind) bodyExtractor {
	switch kind {
	case endpointRegistryMonitor:
		return extractMonitorProjectID
	case endpointRegistryIaCShare:
		return extractIaCShareProjectID
	case endpointDeeproxyReport:
		return extractDeeproxyReportProjectID
	case endpointTestComponents:
		return extractComponentsProjectID
	case endpointTestCreate:
		return extractCreateTestID
	default:
		return nil
	}
}

// extractMonitorProjectID reads the project ID from a monitor response, whose
// uri field is serialized after licensesPolicy and so can sit megabytes in.
func extractMonitorProjectID(r io.Reader) (string, error) {
	uri, err := findStringField(json.NewDecoder(r), "uri")
	if err != nil {
		return "", err
	}
	return projectIDFromMonitorURI(uri), nil
}

// extractIaCShareProjectID reads the first project ID from an
// iac-cli-share-results response, whose keys are project names. One invocation
// reports one entity, so the first is enough.
func extractIaCShareProjectID(r io.Reader) (string, error) {
	var projectID string

	dec := json.NewDecoder(r)
	err := eachKey(dec, func(key string) (bool, error) {
		if isIaCShareMetadataKey(key) {
			return false, skipValue(dec)
		}

		value, isString, err := nextStringValue(dec)
		if err != nil || !isString {
			return false, err
		}

		projectID = parseUUID(value)
		return projectID != "", nil
	})

	return projectID, err
}

func isIaCShareMetadataKey(key string) bool {
	switch strings.ToLower(key) {
	case "ok", "meta":
		return true
	default:
		return false
	}
}

// extractCreateTestID reads the test ID from a create test response.
func extractCreateTestID(r io.Reader) (string, error) {
	id, err := findStringField(json.NewDecoder(r), "data", "id")
	if err != nil {
		return "", err
	}
	return parseUUID(id), nil
}

// extractComponentsProjectID reads the project ID of the first successful SAST
// component of a components response.
func extractComponentsProjectID(r io.Reader) (string, error) {
	var projectID string

	dec := json.NewDecoder(r)
	err := walkTo(dec, []string{"data"}, func() error {
		id, err := firstSastProjectID(dec)
		projectID = id
		return err
	})

	return projectID, err
}

// firstSastProjectID scans a components array for the first successful SAST
// component. Components are decoded one at a time, so only one is ever held.
func firstSastProjectID(dec *json.Decoder) (string, error) {
	if err := expectDelim(dec, '['); err != nil {
		return "", err
	}

	for dec.More() {
		var component struct {
			Attributes struct {
				Type    string `json:"type"`
				Success bool   `json:"success"`
				Webui   struct {
					ProjectID string `json:"project_id"`
				} `json:"webui"`
			} `json:"attributes"`
		}
		if err := dec.Decode(&component); err != nil {
			return "", err
		}

		if !strings.EqualFold(component.Attributes.Type, "sast") || !component.Attributes.Success {
			continue
		}
		if projectID := parseUUID(component.Attributes.Webui.ProjectID); projectID != "" {
			return projectID, nil
		}
	}

	return "", nil
}

// extractDeeproxyReportProjectID reads the project ID from a legacy Code
// deeproxy report response, which arrives gzipped.
func extractDeeproxyReportProjectID(r io.Reader) (string, error) {
	reader, err := gzip.NewReader(r)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	projectID, err := findStringField(json.NewDecoder(reader), "uploadResult", "projectId")
	if err != nil {
		return "", err
	}
	return parseUUID(projectID), nil
}

// extractAIBomUploadRevisionID reads the revision ID from an AI-BOM upload
// request, whose remainder is the document being uploaded.
func extractAIBomUploadRevisionID(r io.Reader) (string, error) {
	revisionID, err := findStringField(json.NewDecoder(r), "data", "attributes", "upload_revision_id")
	if err != nil {
		return "", err
	}
	return parseUUID(revisionID), nil
}

// createTestReport is what a create test request says about publishing: whether
// it asks for a report, and whether the request could be read to tell.
type createTestReport struct {
	report bool
	known  bool
}

// extractCreateTestReport reports whether a create test request asks for a
// report. Two request shapes are in use - the legacy config block and the Code
// API's configuration block - so one pass watches for both.
func extractCreateTestReport(r io.Reader) (createTestReport, error) {
	var legacy struct {
		PublishReport bool `json:"publish_report"`
		Monitor       bool `json:"monitor"`
	}
	var current struct {
		Output struct {
			Report bool `json:"report"`
		} `json:"output"`
	}

	dec := json.NewDecoder(r)
	err := walkTo(dec, []string{"data", "attributes"}, func() error {
		return eachKey(dec, func(key string) (bool, error) {
			switch key {
			case "config":
				return false, dec.Decode(&legacy)
			case "configuration":
				return false, dec.Decode(&current)
			default:
				return false, skipValue(dec)
			}
		})
	})
	if err != nil {
		return createTestReport{}, err
	}

	report := current.Output.Report
	switch {
	case legacy.Monitor:
		report = false
	case legacy.PublishReport:
		report = true
	}

	return createTestReport{report: report, known: true}, nil
}

// projectIDFromMonitorURI extracts a project ID from a monitor API response
// URI, of the form https://app.snyk.io/org/{org}/project/{uuid}/history/{id}.
func projectIDFromMonitorURI(uri string) string {
	const projectPrefix = "/project/"
	idx := strings.Index(uri, projectPrefix)
	if idx < 0 {
		return ""
	}

	start := idx + len(projectPrefix)
	if start+uuidLen > len(uri) {
		return ""
	}
	if start+uuidLen < len(uri) && uri[start+uuidLen] != '/' {
		return ""
	}

	return parseUUID(uri[start : start+uuidLen])
}
