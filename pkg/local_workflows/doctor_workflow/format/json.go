package format

import (
	"encoding/json"
	"io"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
)

// FormatJSON writes the report as JSON to w.
func FormatJSON(w io.Writer, report *diagnosis.DoctorReport) error {
	return json.NewEncoder(w).Encode(report)
}
