package present

import "snyk.io/dragonfly/pkg/schemas:testapi"

input: _

input: {
    test: testapi.#TestResource
    findings: [...testapi.#FindingResource]
}

// This should align with
// LocalFinding definition
output: {
    findings: [ for finding in input.findings {
        attributes: finding.attributes
        id: finding.id
        relationships: finding.relationships
        type: finding.type
    } ]
    summary: input.test.attributes.summary
    outcome: input.test.attributes.outcome
}
