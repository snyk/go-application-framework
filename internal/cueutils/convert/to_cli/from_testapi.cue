package present

import "snyk.io/dragonfly/pkg/schemas:testapi"

input: _

input: {
    test: testapi.#TestResource
    findings: [...testapi.#FindingResource]
}

output: {
    findings: [ for finding in input.findings { finding.attributes } ]
    summary: input.test.attributes.summary
    outcome: input.test.attributes.outcome
    severity_order: ["high", "medium", "low"]
}
