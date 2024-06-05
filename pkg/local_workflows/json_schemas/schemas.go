package json_schemas

import "time"

const ScanDoneEventSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": [
    "data"
  ],
  "properties": {
    "data": {
      "type": "object",
      "required": [
        "type",
        "attributes"
      ],
      "properties": {
        "type": {
          "type": "string",
          "description": "The type of data (\"analytics\")."
        },
        "attributes": {
          "type": "object",
          "required": [
            "device_id",
            "application",
            "application_version",
            "os",
            "arch",
            "integration_name",
            "integration_version",
            "integration_environment",
            "integration_environment_version",
            "event_type",
            "status",
            "scan_type",
            "unique_issue_count",
            "duration_ms",
            "timestamp_finished"
          ],
          "properties": {
            "device_id": {
              "type": "string",
              "description": "The unique identifier for the device."
            },
            "application": {
              "type": "string",
              "description": "The application name."
            },
            "application_version": {
              "type": "string",
              "description": "The version of the application."
            },
            "os": {
              "type": "string",
              "description": "The operating system."
            },
            "arch": {
              "type": "string",
              "description": "The architecture (AMD64, ARM64, 386, ALPINE)."
            },
            "integration_name": {
              "type": "string",
              "description": "The name of the integration."
            },
            "integration_version": {
              "type": "string",
              "description": "The version of the integration."
            },
            "integration_environment": {
              "type": "string",
              "description": "The environment for the integration (e.g., IntelliJ Ultimate, Pycharm)."
            },
            "integration_environment_version": {
              "type": "string",
              "description": "The version of the integration environment (e.g. 2023.3)"
            },
            "event_type": {
              "type": "string",
              "description": "The type of event (e.g., Scan done)."
            },
            "status": {
              "type": "string",
              "description": "The status of the event (e.g., Succeeded)."
            },
            "scan_type": {
              "type": "string",
              "description": "The scan type (e.g., Snyk Open Source)."
            },
            "unique_issue_count": {
              "type": "object",
              "required": [
                "critical",
                "high",
                "medium",
                "low"
              ],
              "properties": {
                "critical": {
                  "type": "integer",
                  "description": "The count of critical issues."
                },
                "high": {
                  "type": "integer",
                  "description": "The count of high issues."
                },
                "medium": {
                  "type": "integer",
                  "description": "The count of medium issues."
                },
                "low": {
                  "type": "integer",
                  "description": "The count of low issues."
                }
              },
              "description": "The count of unique issues."
            },
            "duration_ms": {
              "type": "string",
              "description": "The scan duration in milliseconds."
            },
            "timestamp_finished": {
              "type": "string",
              "format": "date-time",
              "description": "The timestamp when the scan was finished in UTC (Zulu time)."
            }
          }
        }
      }
    }
  }
}
`

type UniqueIssueCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type ScanDoneEvent struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			DeviceId                      string           `json:"device_id"`
			Application                   string           `json:"application"`
			ApplicationVersion            string           `json:"application_version"`
			Os                            string           `json:"os"`
			Arch                          string           `json:"arch"`
			IntegrationName               string           `json:"integration_name"`
			IntegrationVersion            string           `json:"integration_version"`
			IntegrationEnvironment        string           `json:"integration_environment"`
			IntegrationEnvironmentVersion string           `json:"integration_environment_version"`
			EventType                     string           `json:"event_type"`
			Status                        string           `json:"status"`
			ScanType                      string           `json:"scan_type"`
			UniqueIssueCount              UniqueIssueCount `json:"unique_issue_count"`
			DurationMs                    string           `json:"duration_ms"`
			TimestampFinished             time.Time        `json:"timestamp_finished"`
			Path                          string           `json:"path,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}
