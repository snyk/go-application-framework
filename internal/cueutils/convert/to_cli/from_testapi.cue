package present

import "snyk.io/dragonfly/pkg/schemas:testapi"

input: _

input: {
	test: testapi.#SchemaMap["types.TestResource"]
	findings: [...testapi.#SchemaMap["types.FindingResource"]]
}

// This should align with
// LocalFinding definition
output: {
	findings: [for finding in input.findings {
		attributes:    finding.attributes
		id:            finding.id
		relationships: finding.relationships
		type:          finding.type
	}]
	outcome:    input.test.attributes.outcome
	rules:      input.rules
	newSummary: input.test.attributes.newSummary
	summary:    input.test.attributes.summary
}
