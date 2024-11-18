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
	test: testapi.#SchemaMap["types.TestResource"]
	findings: [...testapi.#SchemaMap["types.FindingResource"]]
}

// TODO: Inject from runtime context
_summary: {
	artifacts: 0
	counts: {
		count:            0
		count_suppressed: 0
		count_adjusted:   0

		count_by: severity: {}
		count_by_suppressed: severity: { "high": 0, "medium": 0, "low": 0 }
		count_by_adjusted: severity: {}
		count_key_order_asc: {
			severity: []
		}
	}
	// TODO: this needs to be updated to support n runs
	coverage: list.Concat([for run in input.runs {
		[for coverage in run.properties.coverage {
			{
				files:       coverage.files
				isSupported: coverage.isSupported
				lang:        coverage.lang
				type:        coverage.type
			}
		}]
	}])
	path: ""
	type: ""
}

// Transform the input into the output
output: test: {
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
}

output: findings: [for finding in _findings {
	{
		// TODO
		id:         uuid.SHA1("be52d740-04f5-44da-8e17-1cf03d2281d7", finding.fingerprint[0].value)
		type:       "findings"
		attributes: finding
		relationships: {}
	}
}]

// TODO remove 0
// TODO: this needs to be updated to support n runs
output: rules: list.Concat([for run in input.runs {
	[for rule in run.tool.driver.rules {
		{
			id:   rule.id
			name: rule.name
			shortDescription: {
				text: rule.shortDescription.text
			}
			defaultConfiguration: {
				level: rule.defaultConfiguration.level
			}
			help: {
				markdown: rule.help.markdown
				text:     rule.help.text
			}
			properties: {
				tags:                      rule.properties.tags
				categories:                rule.properties.categories
				exampleCommitDescriptions: rule.properties.exampleCommitDescriptions
				exampleCommitFixes:        rule.properties.exampleCommitFixes
				precision:                 rule.properties.precision
				repoDatasetSize:           rule.properties.repoDatasetSize
				cwe:                       rule.properties.cwe
			}
		}
	}]
}])

// Transform the input
// TODO: this needs to be updated to support n runs
_findings: list.Sort(list.Concat([for run in input.runs {
	let _rules = {for rule in run.tool.driver.rules {
		"\(rule.id)": rule
	}
	}
	[for result in run.results {
		let _rule = _rules[result.ruleId]
		{
			referenceId: {
				identifier: result.ruleId
				index:      result.ruleIndex
			}
			fingerprint: [for k, v in result.fingerprints {
				{
					scheme: [
						if k == "0" {"code-sast-v0"},
						if k == "1" {"code-sast-v1"},
						k,
					][0]
					value: v
				}
			}]
			// TODO
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
				if result.properties != _|_ {
					if result.properties.priorityScore != _|_ {
						priority: {
							factors: [for f in result.properties.priorityScoreFactors {
								{
									factor: "vulnerability-fact"
									name:   f.type
									value:  f.label
								}
							}]
							score: result.properties.priorityScore
						}
					}
				}
				severity: {
					let _ruleLevel = _rules[result.ruleId].defaultConfiguration.level
					value: [
						if _ruleLevel == "error" {"high"},
						if _ruleLevel == "warning" {"medium"},
						if _ruleLevel == "note" {"low"},
						"none",
					][0]
				}
				severity_method: "CVSSv3" // TODO double check if this is correct
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
						details: {
							category:   result.suppressions[0].properties.category
							expiration: *result.suppressions[0].properties.expiration | ""
							ignoredOn:  result.suppressions[0].properties.ignoredOn
							ignoredBy: {
								name:  result.suppressions[0].properties.ignoredBy.name
								email: result.suppressions[0].properties.ignoredBy.email
							}
						}
					}
				}
			}

			if result.codeFlows != _|_ {
				codeFlows: [for cl in result.codeFlows {
					threadFlows: [for tf in cl.threadFlows {
						locations: [for loc in tf.locations {
							filepath:              loc.location.physicalLocation.artifactLocation.uri
							original_start_line:   loc.location.physicalLocation.region.startLine
							original_end_line:     loc.location.physicalLocation.region.endLine
							original_start_column: loc.location.physicalLocation.region.startColumn
							original_end_column:   loc.location.physicalLocation.region.endColumn
						}]
					}]
				},
				]
			}
		}
	}]
}]), {T: _, x: T, y: T, less: x.rating.severity.value < y.rating.severity.value})
