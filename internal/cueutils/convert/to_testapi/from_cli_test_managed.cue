package from_cli_test_managed

import "list"
import "strings"
import "uuid"

import "snyk.io/dragonfly/pkg/schemas:cli_test_managed"
import "snyk.io/dragonfly/pkg/schemas:testapi"

input: _

// Validate the input as conforming to the `snyk test --json` schema.
input: cli_test_managed.#Result

// Validate the output as conforming to a composition of
// a Test resource and an array of Finding resources.
output: {
    test: testapi.#TestResource
    findings: [...testapi.#FindingResource]
}

// TODO: Inject from runtime context
context: {
    org: id: "f640a238-ee99-44d4-8d49-42ec6af96bc6"
    test: id: "12d77614-e02d-44d7-bb52-3a1b179d5890"
}

_summary: testapi.#FindingsSummary
_summary: {
    counts: {
        count: 0
        count_suppressed: 0
        count_adjusted: 0

        count_by: severity: {
            critical: 0
            high: 0
            medium: 0
            low: 0
            none: 0
        }
        count_by_adjusted: severity: {
            critical: 0
            high: 0
            medium: 0
            low: 0
            none: 0
        }
        count_key_order_asc: {
            severity: ["none", "low", "medium", "high", "critical"]
        }
    }
}

// Transform the input into the output
output: test: {
    id: context.test.id
    type: "tests"
    attributes: {
        state: {}
        outcome: result: [
            if input.ok { "pass" },
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
output: findings: [ for finding in _findings {
    {
        id: uuid.SHA1("be52d740-04f5-44da-8e17-1cf03d2281d7", finding.fingerprint.value),
        type: "findings"
        attributes: finding
        relationships: {}
    }
}]

_findings: list.Sort([ for vuln in input.vulnerabilities {
    let _fingerprintValue = "\( vuln.name ):\( vuln.id ):\( strings.Join(vuln.from, "/"))"
    {
        fingerprint: {
            scheme: "sca-problem"
            value: _fingerprintValue
        }
        component: {
            name: input.displayTargetFile
            scan_type: "sca"
        }
        message: {
            header: "\(vuln.title)"
            let _descLen = len(strings.Runes(vuln.description))
            text: strings.SliceRunes(vuln.description, 0, [
                if _descLen < 2000 { _descLen },
                2000
            ][0])
        }
        rating: {
            severity: {
                value: vuln.severity
            }
            severity_method: "CVSSv31"
        }
        locations: [{
            dependency_path: [for semver in vuln.from {
                let parts = strings.SplitN(semver, "@", 2)
                package_name: parts[0]
                package_version: parts[1]
            }]
        }]
    }
}], { T: _, x: T, y: T, less: x.rating.severity.value < y.rating.severity.value })
