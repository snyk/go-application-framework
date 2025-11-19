package output_workflow

import "github.com/snyk/go-application-framework/internal/presenters"

const (
	OUTPUT_CONFIG_KEY_JSON         = "json"
	OUTPUT_CONFIG_KEY_JSON_FILE    = "json-file-output"
	OUTPUT_CONFIG_KEY_SARIF        = "sarif"
	OUTPUT_CONFIG_KEY_SARIF_FILE   = "sarif-file-output"
	OUTPUT_CONFIG_TEMPLATE_FILE    = "internal_template_file"
	OUTPUT_CONFIG_KEY_FILE_WRITERS = "internal_output_file_writers"
	DEFAULT_WRITER                 = "default"
	DEFAULT_MIME_TYPE              = presenters.DefaultMimeType
	SARIF_MIME_TYPE                = presenters.ApplicationSarifMimeType
	JSON_MIME_TYPE                 = presenters.ApplicationJSONMimeType
)

// DefaultTemplateFiles is an instance of TemplatePathsStruct with the template paths.
var DefaultTemplateFiles = presenters.DefaultTemplateFiles
var ApplicationSarifTemplates = presenters.ApplicationSarifTemplates
