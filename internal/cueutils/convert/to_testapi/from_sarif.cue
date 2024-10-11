package from_sarif

import "list"

import "uuid"

import "snyk.io/dragonfly/pkg/schemas:sarif"

import "snyk.io/dragonfly/pkg/schemas:testapi"

input: _

// validate the input as conforming to the /v1/test-dep-graph we've imported & embedded `go generate`
input: sarif

// Validate the output as conforming to a composition of
// a Test resource and an array of Finding resources.
output: {
	test: testapi.#TestResource
	findings: [...testapi.#FindingResource]
}

// TODO: Inject from runtime context
context: {
	org: id:  "f640a238-ee99-44d4-8d49-42ec6af96bc6"
	test: id: "12d77614-e02d-44d7-bb52-3a1b179d5890"
}

_summary: testapi.#FindingsSummary
// TODO: Inject from runtime context
_summary: {
	counts: {
		count:            0
		count_suppressed: 0
		count_adjusted:   0

		count_by: severity: {
			critical: 0
			high:     0
			medium:   0
			low:      0
			none:     0
		}
		count_by_adjusted: severity: {
			critical: 0
			high:     0
			medium:   0
			low:      0
			none:     0
		}
		count_key_order_asc: {
			severity: ["none", "low", "medium", "high", "critical"]
		}
	}
}

// Transform the input into the output
output: test: {
	id:   context.test.id
	type: "tests"
	attributes: {
		state: {
			status: "done"
		}
		outcome: result: [
			if len(_findings) == 0 {"pass"},
			"fail",
		][0]
		summary: _summary
	}
	relationships: {
		findings: {
			links: {
				related: "/orgs/\(context.org.id)/test/\(context.test.id)/findings"
			}
		}
	}
}

output: findings: [for finding in _findings {
	{
		id:         uuid.SHA1("be52d740-04f5-44da-8e17-1cf03d2281d7", finding.fingerprint.value)
		type:       "findings"
		attributes: finding
		relationships: {}
	}
}]

// Transform the input
_findings: list.Sort(list.Concat([for run in input.runs {
	let _rules = {for rule in run.tool.driver.rules {
		"\(rule.id)": rule
	}
	}
	[for result in run.results {
		let _rule = _rules[result.ruleId]
		{
			fingerprint: {
				scheme: "code-sast-v0"
				// TODO: improve this with a decomped stable finding ID function!
				value: string
			} & {
				value: [for fp in [
					result.fingerprints["identity"],
					result.fingerprints["1"],
					result.fingerprints["0"],
					"missing-fingerprint",
				] if fp != _|_ {fp}][0]
			}
			component: {
				name:      "."
				scan_type: "sast"
			}
			message: {
				header:    _rule.shortDescription.text
				text:      result.message.text
				markdown:  result.message.markdown
				arguments: result.message.arguments
			}
			rating: {
				severity: {
					let _ruleLevel = _rules[result.ruleId].defaultConfiguration.level
					value: [
						if _ruleLevel == "error" {"high"},
						if _ruleLevel == "warning" {"medium"},
						if _ruleLevel == "note" {"low"},
						"none",
					][0]
				}
				severity_method: "CVSSv3"
			}
			locations: [for location in result.locations
				if location.physicalLocation != _|_ {
					let _pl = location.physicalLocation
					{
						source_locations: {
							filepath:              _pl.artifactLocation.uri
							original_start_line:   _pl.region.startLine
							original_end_line:     _pl.region.endLine
							original_start_column: _pl.region.startColumn
							original_end_column:   _pl.region.endColumn
						}
					}
				}]
			if result.suppressions != _|_ {
				if result.suppressions != null {
					suppression: {
						kind: "ignored"
						if len(result.suppressions) > 0 {
							justification: result.suppressions[0].justification
						}
					}
				}
			}
		}
	}]
}]), {T: _, x: T, y: T, less: x.rating.severity.value < y.rating.severity.value})
