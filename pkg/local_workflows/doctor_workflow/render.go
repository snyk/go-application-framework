package doctor_workflow

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/bundle"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/llm"
)

// renderDiagnosis presents the LLM result as a finding-style block, the
// same visual language as the CLI's test output:
//
//	Snyk Doctor Diagnosis
//
//	 ✗ [DIAGNOSIS] Organization not accessible
//	   Info: You specified --org=abc, but ...
//
//	   Evidence:
//	    - ...
//
//	   Suggested fix:
//	    1. ...
func renderDiagnosis(diagnosis llm.Diagnosis, err error, color bool) string {
	st := bundle.NewStyles(color)

	var sb strings.Builder
	bundle.Section(&sb, "Snyk Doctor Diagnosis", st)

	if err != nil {
		bundle.WriteBlockHeader(&sb, st.Bad("✗"), st.Bad("[FAILED]"), "Diagnosis unavailable", st)
		bundle.WriteWrapped(&sb, err.Error(), "   Error: ", "          ")
		fmt.Fprintf(&sb, "\n   Re-run with --%s to get the consolidated report for a support ticket.\n", includeReportFlag)
		return sb.String()
	}

	if diagnosis.Title == "" {
		// model didn't produce the structured shape; show what it said
		bundle.WriteBlockHeader(&sb, st.Bad("✗"), st.Bad("[DIAGNOSIS]"), "Unstructured model response", st)
		for _, line := range strings.Split(strings.TrimSpace(diagnosis.Raw), "\n") {
			fmt.Fprintf(&sb, "   %s\n", line)
		}
		return sb.String()
	}

	bundle.WriteBlockHeader(&sb, st.Bad("✗"), st.Bad("[DIAGNOSIS]"), diagnosis.Title, st)
	bundle.WriteWrapped(&sb, diagnosis.RootCause, "   Info: ", "         ")

	if len(diagnosis.Evidence) > 0 {
		fmt.Fprintf(&sb, "\n   %s\n", st.Bold("Evidence:"))
		for _, line := range diagnosis.Evidence {
			bundle.WriteWrapped(&sb, trimQuotedMarkers(line), "    "+st.Dim("-")+" ", "      ")
		}
	}

	if len(diagnosis.SuggestedFix) > 0 {
		fmt.Fprintf(&sb, "\n   %s\n", st.Bold("Suggested fix:"))
		for i, step := range diagnosis.SuggestedFix {
			number := fmt.Sprintf("%d.", i+1)
			bundle.WriteWrapped(&sb, trimStepNumbering(step), "    "+st.Dim(number)+" ", "       ")
		}
	}

	return sb.String()
}

// trimQuotedMarkers drops list/failure glyphs and JSON punctuation the
// model copied from the report, so evidence bullets read clean.
func trimQuotedMarkers(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimRight(line, ",")
	line = strings.Trim(line, `'"`)
	return strings.TrimLeft(line, "✗•- ")
}

var stepNumberRe = regexp.MustCompile(`^\s*\d+[.)]\s*`)

// trimStepNumbering drops the model's own "1. " prefixes so steps aren't
// numbered twice.
func trimStepNumbering(step string) string {
	return stepNumberRe.ReplaceAllString(strings.TrimSpace(step), "")
}
