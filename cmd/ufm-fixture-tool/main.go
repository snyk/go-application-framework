// Command ufm-fixture-tool redacts a workflow data dump for use as a
// deterministic test fixture. UUIDs, emails, and sensitive metadata
// (including stable org-scoped URLs) are replaced with placeholders.
//
// Usage:
//
//	# Step 1 — dump workflow data to disk via built-in env vars:
//	SNYK_TMP_PATH=./dump INTERNAL_IN_MEMORY_THRESHOLD_BYTES=1 INTERNAL_CLEANUP_GLOBAL_TEMP_DIR_ENABLED=false \
//	  snyk secrets test . --report --org=my-org
//
//	# Step 2 — redact the dump into a fixture:
//	go run ./cmd/ufm-fixture-tool --input=./dump/workflow.TestResult.12345 --output=my_fixture.testresult.json
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/cmd/ufm-fixture-tool/redact"
)

func main() {
	input := flag.String("input", "", "path to the workflow data dump file (required)")
	output := flag.String("output", "", "path for the redacted output file (optional; defaults to <input>_redacted.json)")
	flag.Parse()

	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: --input is required (path to the dump file)")
		os.Exit(1)
	}
	if *output == "" {
		if strings.HasSuffix(*input, ".json") {
			*output = strings.TrimSuffix(*input, ".json") + "_redacted.json"
		} else {
			*output = *input + "_redacted.json"
		}
	}

	raw, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}

	redacted, err := redact.Fixture(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error redacting: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, redacted, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s (%d bytes)\n", *output, len(redacted))
}
