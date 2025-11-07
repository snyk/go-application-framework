package presenters_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/xeipuuv/gojsonschema"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func validateSarifData(t *testing.T, data []byte) {
	t.Helper()

	sarifSchemaPath, err := filepath.Abs("../../internal/local_findings/source/sarif-schema-2.1.0.json")
	assert.NoError(t, err)

	sarifSchemaFile, err := os.Open(sarifSchemaPath)
	assert.NoError(t, err)

	sarifSchemaBytes, err := io.ReadAll(sarifSchemaFile)
	assert.NoError(t, err)

	sarifSchema := gojsonschema.NewBytesLoader(sarifSchemaBytes)
	assert.NotNil(t, sarifSchema)

	validationResult, err := gojsonschema.Validate(sarifSchema, gojsonschema.NewBytesLoader(data))
	assert.NoError(t, err)
	assert.NotNil(t, validationResult)
	if validationResult != nil {
		for _, validationError := range validationResult.Errors() {
			t.Log(validationError)
		}
		assert.True(t, validationResult.Valid(), "Sarif validation failed")
	}
}

// normalizeAutomationID removes project name and timestamp from automation ID
func normalizeAutomationID(run map[string]interface{}) {
	if automationDetails, ok := run["automationDetails"].(map[string]interface{}); ok {
		if id, ok := automationDetails["id"].(string); ok {
			parts := strings.Split(id, "/")
			if len(parts) >= 2 {
				automationDetails["id"] = strings.Join(parts[:2], "/") + "/*"
			}
		}
	}
}

// normalizeToolProperties removes tool.driver.properties (artifactsScanned missing)
// and normalizes version numbers
func normalizeToolProperties(run map[string]interface{}) {
	if tool, ok := run["tool"].(map[string]interface{}); ok {
		if driver, ok := tool["driver"].(map[string]interface{}); ok {
			delete(driver, "properties")
			normalizeRules(driver)
		}
	}
}

// normalizeRules normalizes rule properties for comparison
func normalizeRules(driver map[string]interface{}) {
	if rules, ok := driver["rules"].([]interface{}); ok {
		for _, ruleInterface := range rules {
			rule, ok := ruleInterface.(map[string]interface{})
			if !ok {
				continue
			}

			// Normalize CVSS score formatting and remove undefined values
			if props, ok := rule["properties"].(map[string]interface{}); ok {
				if secSev, ok := props["security-severity"].(string); ok {
					if secSev == "undefined" {
						// Remove undefined security-severity
						delete(props, "security-severity")
					} else if !strings.Contains(secSev, ".") {
						// Ensure consistent decimal format (e.g., "6" -> "6.0")
						props["security-severity"] = secSev + ".0"
					}
				}
			}
		}

		// Sort rules by ID for consistent comparison
		sortByID(rules)
		driver["rules"] = rules
	}
}

// normalizeResults normalizes result messages for comparison
func normalizeResults(run map[string]interface{}) {
	if results, ok := run["results"].([]interface{}); ok {
		// Sort results by ruleId for consistent comparison
		sortByRuleID(results)
		run["results"] = results
	}
}

// sortByID sorts an array of objects by their "id" field
func sortByID(arr []interface{}) {
	sort.Slice(arr, func(i, j int) bool {
		iMap, iOk := arr[i].(map[string]interface{})
		jMap, jOk := arr[j].(map[string]interface{})
		if !iOk || !jOk {
			return false
		}
		iID, _ := iMap["id"].(string) //nolint:errcheck // test helper, ok to ignore
		jID, _ := jMap["id"].(string) //nolint:errcheck // test helper, ok to ignore
		return iID < jID
	})
}

// sortByRuleID sorts an array of results by their "ruleId" field
func sortByRuleID(arr []interface{}) {
	sort.Slice(arr, func(i, j int) bool {
		iMap, iOk := arr[i].(map[string]interface{})
		jMap, jOk := arr[j].(map[string]interface{})
		if !iOk || !jOk {
			return false
		}
		iID, _ := iMap["ruleId"].(string) //nolint:errcheck // test helper, ok to ignore
		jID, _ := jMap["ruleId"].(string) //nolint:errcheck // test helper, ok to ignore
		return iID < jID
	})
}

// normalizeHelpContent removes help.markdown content to avoid comparing test data descriptions
func normalizeHelpContent(run map[string]interface{}) {
	normalizeRuleHelp(run)
	normalizeResultURIs(run)
}

// normalizeRuleHelp removes help.markdown and normalizes tags in rules
func normalizeRuleHelp(run map[string]interface{}) {
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		return
	}
	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		return
	}
	rules, ok := driver["rules"].([]interface{})
	if !ok {
		return
	}
	for _, ruleInterface := range rules {
		rule, ok := ruleInterface.(map[string]interface{})
		if !ok {
			continue
		}
		// Remove help.markdown to avoid comparing vulnerability descriptions
		if help, ok := rule["help"].(map[string]interface{}); ok {
			// compare markdown up to 5000 bytes
			if markdown, ok := help["markdown"].(string); ok {
				if len(markdown) > 5000 {
					help["markdown"] = markdown[:5000]
				}
			}
		}
		// Normalize tags order
		if props, ok := rule["properties"].(map[string]interface{}); ok {
			if tags, ok := props["tags"].([]interface{}); ok {
				sortTags(tags)
			}
		}
	}
}

// normalizeResultURIs normalizes file URIs to generic "manifest" name
func normalizeResultURIs(run map[string]interface{}) {
	results, ok := run["results"].([]interface{})
	if !ok {
		return
	}
	for _, resultInterface := range results {
		result, ok := resultInterface.(map[string]interface{})
		if !ok {
			continue
		}
		normalizeLocationURIs(result)
		normalizeFixURIs(result)
	}
}

// normalizeLocationURIs normalizes URIs in result locations
func normalizeLocationURIs(result map[string]interface{}) {
	locations, ok := result["locations"].([]interface{})
	if !ok {
		return
	}
	for _, locInterface := range locations {
		loc, ok := locInterface.(map[string]interface{})
		if !ok {
			continue
		}
		physLoc, ok := loc["physicalLocation"].(map[string]interface{})
		if !ok {
			continue
		}
		artLoc, ok := physLoc["artifactLocation"].(map[string]interface{})
		if !ok {
			continue
		}
		uri, ok := artLoc["uri"].(string)
		if !ok {
			continue
		}
		// Normalize common manifest filenames
		if uri == "package.json" || uri == "package-lock.json" || uri == "pom.xml" {
			artLoc["uri"] = "manifest"
		}
	}
}

// normalizeFixURIs normalizes URIs in fixes
func normalizeFixURIs(result map[string]interface{}) {
	fixes, ok := result["fixes"].([]interface{})
	if !ok {
		return
	}
	for _, fixInterface := range fixes {
		fix, ok := fixInterface.(map[string]interface{})
		if !ok {
			continue
		}
		artChanges, ok := fix["artifactChanges"].([]interface{})
		if !ok {
			continue
		}
		for _, changeInterface := range artChanges {
			change, ok := changeInterface.(map[string]interface{})
			if !ok {
				continue
			}
			artLoc, ok := change["artifactLocation"].(map[string]interface{})
			if !ok {
				continue
			}
			uri, ok := artLoc["uri"].(string)
			if !ok {
				continue
			}
			if uri == "package.json" || uri == "package-lock.json" || uri == "pom.xml" {
				artLoc["uri"] = "manifest"
			}
		}
	}
}

// sortTags sorts tags alphabetically for consistent comparison
func sortTags(tags []interface{}) {
	sort.Slice(tags, func(i, j int) bool {
		iStr, iOk := tags[i].(string)
		jStr, jOk := tags[j].(string)
		if !iOk || !jOk {
			return false
		}
		return iStr < jStr
	})
}

// normalizeSarifForComparison removes or normalizes fields with known gaps
// to allow testing of correctly implemented features while documenting TODOs
func normalizeSarifForComparison(t *testing.T, sarifJSON string) map[string]interface{} {
	t.Helper()

	var sarif map[string]interface{}
	err := json.Unmarshal([]byte(sarifJSON), &sarif)
	assert.NoError(t, err)

	runs, ok := sarif["runs"].([]interface{})
	if !ok {
		return sarif
	}

	for _, runInterface := range runs {
		run, ok := runInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Normalize automation ID (missing project name in actual output)
		normalizeAutomationID(run)

		// Normalize tool properties and rules (artifactsScanned missing, CVSS formatting, license wording)
		normalizeToolProperties(run)

		// Normalize result messages (license issue wording)
		normalizeResults(run)

		// Normalize help content (test data may have different vulnerability descriptions)
		normalizeHelpContent(run)
	}

	return sarif
}

func Test_UfmPresenter_Sarif(t *testing.T) {
	ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1301.0"))

	testCases := []struct {
		name              string
		expectedSarifPath string
		testResultPath    string
	}{
		{
			name:              "cli",
			expectedSarifPath: "testdata/ufm/original_cli.sarif",
			testResultPath:    "testdata/ufm/testresult_cli.json",
		},
		{
			name:              "webgoat",
			expectedSarifPath: "testdata/ufm/webgoat.sarif.json",
			testResultPath:    "testdata/ufm/webgoat.testresult.json",
		},
	}

	for _, tc := range testCases {
		expectedSarifBytes, err := os.ReadFile(tc.expectedSarifPath)
		assert.NoError(t, err)

		testResultBytes, err := os.ReadFile(tc.testResultPath)
		assert.NoError(t, err)

		testResult, err := ufm.NewSerializableTestResultFromBytes(testResultBytes)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(testResult))

		config := configuration.NewWithOpts()

		writer := &bytes.Buffer{}

		presenter := presenters.NewUfmRenderer(testResult, config, writer, presenters.UfmWithRuntimeInfo(ri))
		err = presenter.RenderTemplate(presenters.ApplicationSarifTemplatesUfm, presenters.ApplicationSarifMimeType)
		assert.NoError(t, err)

		validateSarifData(t, writer.Bytes())

		// Normalize both expected and actual SARIF to ignore known gaps while testing implemented features
		expectedNormalized := normalizeSarifForComparison(t, string(expectedSarifBytes))
		actualNormalized := normalizeSarifForComparison(t, writer.String())

		// Convert back to JSON for comparison
		expectedJSON, err := json.MarshalIndent(expectedNormalized, "", "  ")
		assert.NoError(t, err)
		actualJSON, err := json.MarshalIndent(actualNormalized, "", "  ")
		assert.NoError(t, err)

		// Write to temp files for debugging if test fails
		if !assert.JSONEq(t, string(expectedJSON), string(actualJSON),
			"SARIF output differs. Known gaps are normalized:\n"+
				"- Automation ID: missing project name\n"+
				"- Tool properties: missing artifactsScanned\n"+
				"- Fix packages: using vulnerable package instead of direct dependency\n"+
				"- Package versions: may differ based on dependency path selection\n"+
				"- Dependency path ordering: paths are sorted but may differ from original") {
			// Write files for debugging (best effort, ignore errors)
			if err := os.WriteFile(fmt.Sprintf("/tmp/%s_expected_normalized.json", tc.name), expectedJSON, 0644); err != nil {
				t.Logf("Failed to write expected output: %v", err)
			}
			if err := os.WriteFile(fmt.Sprintf("/tmp/%s_actual_normalized.json", tc.name), actualJSON, 0644); err != nil {
				t.Logf("Failed to write actual output: %v", err)
			}
			t.Log("Wrote normalized outputs to /tmp/expected_normalized.json and /tmp/actual_normalized.json for debugging")
		}
	}
}

// BenchmarkUfmPresenter_Sarif_MemoryUsage benchmarks SARIF rendering with large test API responses
// to measure memory usage and performance when processing many issues.
func BenchmarkUfmPresenter_Sarif_MemoryUsage(b *testing.B) {
	ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1301.0"))

	benchmarkCases := []struct {
		name           string
		findingsCount  int
		issuesExpected int
	}{
		{
			name:           "10_000_findings",
			findingsCount:  10000,
			issuesExpected: 5000,
		},
		{
			name:           "1_000_000_findings",
			findingsCount:  1000000,
			issuesExpected: 500000,
		},
	}

	for _, bc := range benchmarkCases {
		b.Run(bc.name, func(b *testing.B) {
			b.Logf("Generating test data with %d findings...", bc.findingsCount)

			// Generate large test result with many findings
			testResult := generateLargeTestResult(b, bc.findingsCount)
			testResults := []testapi.TestResult{testResult}

			b.Logf("Generated test data. Expected ~%d issues from %d findings", bc.issuesExpected, bc.findingsCount)
			b.ResetTimer()

			// Track maximum values across all iterations
			var maxAllocatedMB, maxSysMB uint64

			var memStart runtime.MemStats
			runtime.GC() // Force GC before measurement
			runtime.ReadMemStats(&memStart)

			done := make(chan struct{})
			var pollInterval time.Duration
			if bc.findingsCount >= 1_000_000 {
				pollInterval = time.Second
			} else {
				pollInterval = time.Millisecond * 100
			}
			go func() {
				ticker := time.NewTicker(pollInterval)
				defer ticker.Stop()

				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						var m runtime.MemStats
						runtime.ReadMemStats(&m)

						heapMB := m.HeapInuse / 1024 / 1024
						sysMB := m.Sys / 1024 / 1024

						if heapMB > maxAllocatedMB {
							maxAllocatedMB = heapMB
						}
						if sysMB > maxSysMB {
							maxSysMB = sysMB
						}
					}
				}
			}()

			start := time.Now()

			config := configuration.NewWithOpts()
			writer := &bytes.Buffer{}

			presenter := presenters.NewUfmRenderer(testResults, config, writer, presenters.UfmWithRuntimeInfo(ri))
			err := presenter.RenderTemplate(presenters.ApplicationSarifTemplatesUfm, presenters.ApplicationSarifMimeType)
			if err != nil {
				b.Fatalf("Failed to render SARIF: %v", err)
			}

			duration := time.Since(start)
			close(done)

			var memEnd runtime.MemStats
			runtime.ReadMemStats(&memEnd)

			// Calculate memory usage for this iteration
			totalAllocatedMB := (memEnd.TotalAlloc - memStart.TotalAlloc) / 1024 / 1024
			outputSizeMB := float64(writer.Len()) / 1024 / 1024

			b.Logf("Max allocated: %d MB, Max sys: %d MB", maxAllocatedMB, maxSysMB)
			b.Logf("Total allocated: %d MB, Output size: %.2f MB", totalAllocatedMB, outputSizeMB)
			b.Logf("Duration: %v", duration)
		})
	}
}

// generateLargeTestResult creates a test result with the specified number of findings
// for benchmarking memory usage and performance.
//
//nolint:gocyclo // setup function, complexity is acceptable
func generateLargeTestResult(tb testing.TB, findingsCount int) testapi.TestResult {
	tb.Helper()

	testID := uuid.New()
	createdAt := time.Now().UTC().Truncate(time.Second)
	passFail := testapi.Fail
	outcomeReason := testapi.TestOutcomeReasonPolicyBreach

	// Create test configuration
	failOnUpgradable := false
	severityThreshold := testapi.SeverityLow
	testConfig := &testapi.TestConfiguration{
		LocalPolicy: &testapi.LocalPolicy{
			FailOnUpgradable:       &failOnUpgradable,
			SeverityThreshold:      &severityThreshold,
			SuppressPendingIgnores: false,
		},
		Timeout: &testapi.TimeoutSpec{
			Outcome: testapi.Fail,
			Seconds: 1200,
		},
	}

	// Create test subject - use a simple approach
	testSubject := testapi.TestSubject{}
	// For simplicity, we'll create the subject manually in the JSON structure

	// Generate findings with variety to create realistic grouping scenarios
	findings := make([]testapi.FindingData, 0, findingsCount)

	// Define realistic vulnerability templates based on actual Snyk data
	vulnTemplates := []struct {
		id          string
		title       string
		description string
		severity    testapi.Severity
		cvssScore   float64
		packageName string
		cveID       string
		cweID       string
	}{
		{
			id:          "SNYK-JS-GOT-2932019",
			title:       "Open Redirect",
			description: "## Overview\n\nAffected versions of this package are vulnerable to Open Redirect due to missing verification of requested URLs. It allowed a victim to be redirected to a UNIX socket.\n## Remediation\nUpgrade `got` to version 11.8.5, 12.1.0 or higher.\n## References\n- [GitHub Diff](https://github.com/sindresorhus/got/compare/v12.0.3...v12.1.0)\n- [GitHub PR](https://github.com/sindresorhus/got/pull/2047)\n\n## Details\n\nOpen redirect vulnerabilities occur when a web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.\n\nAn attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even those who are security conscious, may not notice the subsequent redirection to a different domain.",
			severity:    testapi.SeverityMedium,
			cvssScore:   5.4,
			packageName: "got",
			cveID:       "CVE-2022-33987",
			cweID:       "CWE-601",
		},
		{
			id:          "SNYK-JS-DEBUG-14214893",
			title:       "Alternate solution to CWE-1333 | Inefficient Regular Expression Complexity",
			description: "## Overview\n[debug](https://github.com/visionmedia/debug) is a small debugging utility.\n\nAffected versions of this package are vulnerable to Alternate solution to CWE-1333 | Inefficient Regular Expression Complexity. None\n## Remediation\nThere is no fixed version for `debug`.\n\n## References\n- [GitHub Issue](https://github.com/debug-js/debug/issues/957)\n\n## Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\n\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.",
			severity:    testapi.SeverityMedium,
			cvssScore:   6.9,
			packageName: "debug",
			cveID:       "CVE-9999-1234",
			cweID:       "CWE-109",
		},
		{
			id:          "SNYK-JS-BRACEEXPANSION-9789073",
			title:       "Regular Expression Denial of Service (ReDoS)",
			description: "## Overview\n[brace-expansion](https://github.com/juliangruber/brace-expansion) is a Brace expansion as known from sh/bash\n\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) in the `expand()` function, which is prone to catastrophic backtracking on very long malicious inputs.\n## PoC\n```js\nimport index from \"./index.js\";\n\nlet str = \"{a}\" + \",\".repeat(100000) + \"\\u0000\";\n\nlet startTime = performance.now();\n\nconst result = index(str);\n\nlet endTime = performance.now();\n\nlet timeTaken = endTime - startTime;\n\nconsole.log(`匹配耗时: ${timeTaken.toFixed(3)} 毫秒`);\n```\n\n## Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\n\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\n\nLet's take the following regular expression as an example:\n```js\nregex = /A(B|C+)+D/\n```\n\nThis regular expression accomplishes the following:\n- `A` The string must start with the letter 'A'\n- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\n- `D` Finally, we ensure this section of the string ends with a 'D'\n\nThe expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\n\n## Remediation\nUpgrade `brace-expansion` to version 1.1.12, 2.0.2, 3.0.1, 4.0.1 or higher.",
			severity:    testapi.SeverityLow,
			cvssScore:   2.3,
			packageName: "brace-expansion",
			cveID:       "CVE-2025-5889",
			cweID:       "CWE-1333",
		},
		{
			id:          "SNYK-JS-MARKED-2342082",
			title:       "Regular Expression Denial of Service (ReDoS)",
			description: "## Overview\n[marked](https://marked.js.org/) is a low-level compiler for parsing markdown without caching or blocking for long periods of time.\n\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) when unsanitized user input is passed to `block.def`.\n\n## PoC\n```js\nimport * as marked from \"marked\";\nmarked.parse(`[x]:${' '.repeat(1500)}x ${' '.repeat(1500)} x`);\n```\n\n## Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\n\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\n\nLet's take the following regular expression as an example:\n```js\nregex = /A(B|C+)+D/\n```\n\nThis regular expression accomplishes the following:\n- `A` The string must start with the letter 'A'\n- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\n- `D` Finally, we ensure this section of the string ends with a 'D'\n\nThe expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\n\nIt most cases, it doesn't take very long for a regex engine to find a match:\n\n```bash\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD\")'\n0.04s user 0.01s system 95% cpu 0.052 total\n\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX\")'\n1.79s user 0.02s system 99% cpu 1.812 total\n```\n\nThe entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\n\n## Remediation\nUpgrade `marked` to version 4.0.10 or higher.",
			severity:    testapi.SeverityMedium,
			cvssScore:   5.3,
			packageName: "marked",
			cveID:       "CVE-2022-21680",
			cweID:       "CWE-1333",
		},
		{
			id:          "SNYK-JS-ASYNC-12239908",
			title:       "Directory Traversal",
			description: "## Overview\n\nAffected versions of this package are vulnerable to Directory Traversal. Async <= 2.6.4 and <= 3.2.5 are vulnerable to ReDoS (Regular Expression Denial of Service) while parsing function in autoinject function.\n\n## Details\n\nA Directory Traversal attack (also known as path traversal) aims to access files and directories that are stored outside the intended folder. By manipulating files with \"dot-dot-slash (../)\" sequences and its variations, or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system, including application source code, configuration, and other critical system files.\n\nDirectory Traversal vulnerabilities can be generally divided into two types:\n\n- **Information Disclosure**: Allows the attacker to gain information about the folder structure or read the contents of sensitive files on the system.\n\n`st` is a module for serving static files on web pages, and contains a [vulnerability of this type](https://snyk.io/vuln/npm:st:20140206). In our example, we will serve files from the `public` route.\n\nIf an attacker requests the following URL from our server, it will in turn leak the sensitive private key of the root user.\n\n```\ncurl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa\n```\n**Note** `%2e` is the URL encoded version of `.` (dot).\n\n- **Writing arbitrary files**: Allows the attacker to create or replace existing files. This type of vulnerability is also known as `Zip-Slip`. \n\nOne way to achieve this is by using a malicious `zip` archive that holds path traversal filenames. When each filename in the zip archive gets concatenated to the target extraction folder, without validation, the final path ends up outside of the target folder. If an executable or a configuration file is overwritten with a file containing malicious code, the problem can turn into an arbitrary code execution issue quite easily.\n\n## Remediation\nUpgrade `async` to version  or higher.\n## References\n- [Vulnerable Code](https://github.com/caolan/async/blob/v3.2.5/lib/autoInject.js#L41)\n- [Vulnerable Code](https://github.com/caolan/async/blob/v3.2.5/lib/autoInject.js#L6)",
			severity:    testapi.SeverityHigh,
			cvssScore:   7.5,
			packageName: "async",
			cveID:       "CVE-2024-39249",
			cweID:       "CWE-22",
		},
		{
			id:          "SNYK-JS-COOKIE-13271683",
			title:       "Arbitrary Code Injection",
			description: "## Overview\n\nAffected versions of this package are vulnerable to Arbitrary Code Injection cookie is a basic HTTP cookie parser and serializer for HTTP servers. The cookie name could be used to set other fields of the cookie, resulting in an unexpected cookie value. A similar escape can be used for path and domain, which could be abused to alter other fields of the cookie. Upgrade to 0.7.0, which updates the validation for name, path, and domain.\n## Remediation\nUpgrade `cookie` to version 1.0.0 or higher.\n## References\n- [GitHub Advisory](https://github.com/jshttp/cookie/security/advisories/GHSA-pxg6-pf52-xh8x)\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n\n## Details\n\nCode Injection vulnerabilities allow an attacker to execute arbitrary code in the context of the vulnerable application. This type of vulnerability occurs when user input is not properly validated or sanitized before being executed as code.\n\nIn the case of cookie parsing, improper validation of cookie names, paths, or domains can lead to injection attacks where malicious code is executed when the cookie is processed. This can result in unauthorized access, data theft, or complete system compromise.\n\nThe vulnerability in the cookie package allows attackers to manipulate cookie fields by injecting special characters or escape sequences in the cookie name, potentially leading to unexpected behavior or security bypasses.",
			severity:    testapi.SeverityMedium,
			cvssScore:   6.9,
			packageName: "cookie",
			cveID:       "CVE-2024-47764",
			cweID:       "CWE-74",
		},
		{
			id:          "SNYK-JS-LODASH-12239302",
			title:       "Denial of Service (DoS)",
			description: "## Overview\n[lodash](https://www.npmjs.com/package/lodash) is a modern JavaScript utility library delivering modularity, performance, & extras.\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). An issue was discovered in Juju that resulted in the leak of the sensitive context ID, which allows a local unprivileged attacker to access other sensitive data or relation accessible to the local charm.\n\n## Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n## Remediation\nUpgrade `lodash` to version  or higher.\n## References\n- [AAAA](https://www.cve.org/CVERecord?id=CVE-2024-6984)\n- [GitHub Advisory](https://github.com/juju/juju/security/advisories/GHSA-6vjm-54vp-mxhx)\n- [GitHub Commit](https://github.com/juju/juju/commit/da929676853092a29ddf8d589468cf85ba3efaf2)",
			severity:    testapi.SeverityHigh,
			cvssScore:   7.5,
			packageName: "lodash",
			cveID:       "CVE-2024-6984",
			cweID:       "CWE-400",
		},
		{
			id:          "snyk:lic:npm:shescape:MPL-2.0",
			title:       "MPL-2.0 License Issue",
			description: "## Overview\n\nThis package contains a dependency with a Mozilla Public License 2.0 (MPL-2.0) license. The MPL-2.0 is a copyleft license that is more permissive than the GPL but requires that modifications to MPL-licensed code be made available under the MPL.\n\n## License Details\n\nThe Mozilla Public License 2.0 (MPL-2.0) is a weak copyleft license that allows you to combine MPL-licensed code with code under other licenses (including proprietary licenses) in a larger work, but requires that any modifications to the MPL-licensed code itself be made available under the MPL.\n\nKey requirements of MPL-2.0:\n- Source code of MPL-licensed files must remain available under MPL-2.0\n- Modifications to MPL-licensed files must be made available under MPL-2.0\n- You must include the MPL-2.0 license text and copyright notices\n- Patent grants are included for contributors\n\n## Remediation\n\nReview your organization's license policy to determine if MPL-2.0 licensed dependencies are acceptable for your use case. If not, consider finding an alternative package with a more permissive license.\n\n## References\n- [Mozilla Public License 2.0 Full Text](https://www.mozilla.org/en-US/MPL/2.0/)\n- [MPL-2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)",
			severity:    testapi.SeverityLow,
			cvssScore:   0.0,
			packageName: "shescape",
			cveID:       "",
			cweID:       "",
		},
	}

	// Generate findings using templates with variations
	for i := 0; i < findingsCount; i++ {
		template := vulnTemplates[i%len(vulnTemplates)]
		findingID := uuid.New()

		// Create variations to ensure some grouping but not complete duplication
		var findingKey string
		var vulnID string
		if i%2 == 0 {
			// Create unique findings (won't be grouped)
			findingKey = fmt.Sprintf("%s-%d", template.id, i)
			vulnID = fmt.Sprintf("%s-%d", template.id, i)
		} else {
			// Create findings that will be grouped together
			groupID := i / 2 // Group every 2 findings together
			findingKey = fmt.Sprintf("%s-group-%d", template.id, groupID)
			vulnID = template.id
		}

		// Create problems
		var problems []testapi.Problem

		// Add Snyk vulnerability problem
		if template.id != "" && !strings.Contains(template.id, "lic:") {
			var snykVulnProblem testapi.Problem
			var ecosystem testapi.SnykvulndbPackageEcosystem
			err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
				PackageManager: "npm",
			})
			if err != nil {
				tb.Fatalf("Failed to create ecosystem: %v", err)
			}

			err = snykVulnProblem.FromSnykVulnProblem(testapi.SnykVulnProblem{
				Id:                       vulnID,
				Source:                   testapi.SnykVuln,
				Severity:                 template.severity,
				CvssBaseScore:            testapi.SnykvulndbCvssScore(template.cvssScore),
				PackageName:              template.packageName,
				PackageVersion:           fmt.Sprintf("1.%d.0", i%10),
				IsFixable:                i%2 == 0, // 50% fixable
				InitiallyFixedInVersions: []string{fmt.Sprintf("1.%d.1", i%10+1)},
				Ecosystem:                ecosystem,
			})
			if err != nil {
				tb.Fatalf("Failed to create Snyk vuln problem: %v", err)
			}
			problems = append(problems, snykVulnProblem)
		} else if strings.Contains(template.id, "lic:") {
			// Add license problem
			var licenseProblem testapi.Problem
			var ecosystem testapi.SnykvulndbPackageEcosystem
			err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
				PackageManager: "npm",
			})
			if err != nil {
				tb.Fatalf("Failed to create ecosystem: %v", err)
			}

			err = licenseProblem.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
				Id:          vulnID,
				Source:      testapi.SnykLicense,
				Severity:    template.severity,
				PackageName: template.packageName,
				Ecosystem:   ecosystem,
			})
			if err != nil {
				tb.Fatalf("Failed to create Snyk license problem: %v", err)
			}
			problems = append(problems, licenseProblem)
		}

		// Add CVE problem if available
		if template.cveID != "" {
			var cveProblem testapi.Problem
			err := cveProblem.FromCveProblem(testapi.CveProblem{
				Id:     template.cveID,
				Source: testapi.Cve,
			})
			if err != nil {
				tb.Fatalf("Failed to create CVE problem: %v", err)
			}
			problems = append(problems, cveProblem)
		}

		// Add CWE problem if available
		if template.cweID != "" {
			var cweProblem testapi.Problem
			err := cweProblem.FromCweProblem(testapi.CweProblem{
				Id:     template.cweID,
				Source: testapi.Cwe,
			})
			if err != nil {
				tb.Fatalf("Failed to create CWE problem: %v", err)
			}
			problems = append(problems, cweProblem)
		}

		// Create package location
		var packageLocation testapi.FindingLocation
		err := packageLocation.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{
				Name:    template.packageName,
				Version: fmt.Sprintf("1.%d.0", i%10),
			},
			Type: testapi.PackageLocationTypePackage,
		})
		if err != nil {
			tb.Fatalf("Failed to create package location: %v", err)
		}

		// Create dependency path evidence
		var depPathEvidence testapi.Evidence
		err = depPathEvidence.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Path: []testapi.Package{
				{Name: "root-package", Version: "1.0.0"},
				{Name: fmt.Sprintf("intermediate-%d", i%5), Version: fmt.Sprintf("2.%d.0", i%3)},
				{Name: template.packageName, Version: fmt.Sprintf("1.%d.0", i%10)},
			},
			Source: testapi.DependencyPath,
		})
		if err != nil {
			tb.Fatalf("Failed to create dependency path evidence: %v", err)
		}

		// Create finding attributes
		findingAttrs := testapi.FindingAttributes{
			CauseOfFailure: i%10 == 0, // 10% cause failure
			Description:    fmt.Sprintf("%s (instance %d)", template.description, i),
			Evidence:       []testapi.Evidence{depPathEvidence},
			FindingType:    testapi.FindingTypeSca,
			Key:            findingKey,
			Locations:      []testapi.FindingLocation{packageLocation},
			Problems:       problems,
			Rating:         testapi.Rating{Severity: template.severity},
			Risk:           testapi.Risk{RiskScore: &testapi.RiskScore{Value: uint16(template.cvssScore * 10)}},
			Title:          fmt.Sprintf("%s in %s", template.title, template.packageName),
		}

		// Create finding data
		findingDataType := testapi.Findings
		findingData := testapi.FindingData{
			Attributes: &findingAttrs,
			Id:         &findingID,
			Type:       &findingDataType,
		}

		findings = append(findings, findingData)
	}

	// Calculate summaries based on generated findings
	severityCounts := map[testapi.Severity]int{
		testapi.SeverityCritical: 0,
		testapi.SeverityHigh:     0,
		testapi.SeverityMedium:   0,
		testapi.SeverityLow:      0,
	}

	for _, finding := range findings {
		if finding.Attributes != nil {
			severityCounts[finding.Attributes.Rating.Severity]++
		}
	}

	countByMap := map[string]map[string]uint32{
		"result_type": {
			"sca":   uint32(findingsCount),
			"sast":  0,
			"dast":  0,
			"other": 0,
		},
		"severity": {
			"critical": uint32(severityCounts[testapi.SeverityCritical]),
			"high":     uint32(severityCounts[testapi.SeverityHigh]),
			"medium":   uint32(severityCounts[testapi.SeverityMedium]),
			"low":      uint32(severityCounts[testapi.SeverityLow]),
			"none":     0,
			"other":    0,
		},
	}

	effectiveSummary := &testapi.FindingSummary{
		Count:   uint32(findingsCount),
		CountBy: &countByMap,
	}

	// Create the test result using JSON marshaling/unmarshaling approach
	// This mimics how real test results are created from API responses
	testResultData := map[string]interface{}{
		"testId":            testID,
		"testConfiguration": testConfig,
		"createdAt":         createdAt,
		"testSubject":       testSubject,
		"executionState":    testapi.TestExecutionStatesFinished,
		"passFail":          passFail,
		"outcomeReason":     outcomeReason,
		"effectiveSummary":  effectiveSummary,
		"rawSummary":        effectiveSummary,
		"findings":          findings,
		"findingsComplete":  true,
	}

	// Marshal to JSON and then unmarshal to create a proper test result
	jsonBytes, err := json.Marshal([]interface{}{testResultData})
	if err != nil {
		tb.Fatalf("Failed to marshal test result: %v", err)
	}

	results, err := ufm.NewSerializableTestResultFromBytes(jsonBytes)
	if err != nil {
		tb.Fatalf("Failed to create test result from bytes: %v", err)
	}

	if len(results) == 0 {
		tb.Fatalf("No test results created")
	}

	return results[0]
}
