namespace io.snyk.client.presentation;

/**
 * TestResult represents the top-level result from a Snyk security test. This
 * includes the overall outcome and enriched findings.
 */
model TestResult {
    outcome: TestOutcome;
    exitCode: integer;
    findings: Finding[];
}

/**
 * TestOutcome represents how the security test should be interpreted and acted
 * upon. Did the test pass or fail according to findings, ignores and policy?
 * Did an error interfere with the test making the results indeterminate?
 */
enum TestOutcome {
    Pass,
    Fail,
    Error,
}

/**
 * Finding represents an individual security vulnerability found by Snyk when
 * scanning an asset, enriched with risk context and policy decisions.
 */
model Finding {
    id: FindingID;
    scanType: ScanType;
    location: Location;
    vulnerabilities: Vulnerability[];
    remediations: Remediation[];
    severity: Severity;
    ignore: Ignore;
}

/**
 * FindingID uniquely identifies a Finding. It should be considered a stable
 * primary key for a particular security finding on a particular asset.
 */
scalar FindingID extends string;

/**
 * ScanType represents one of the security scan types supported by Snyk.
 */
enum ScanType {
    OpenSource,
    Container,
    Code,
    IaC,
}

/**
 * Severity represents the overall impact of a security Finding.
 */
model Severity {
    level: SeverityLevel;
    originalLevel?: SeverityLevel;
}

/**
 * SeverityLevel enumerates the levels of impact severity.
 */
enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
}

/**
 * Ignore represents the application of a directive to ignore a particular
 * Finding. This directive may have come from a developer or application
 * security authority indicating the finding is a false positive or irrelevant
 * to the application's threat model.
 */
model Ignore {
    ignored: boolean;
    reason?: string;
}

/**
 * Location represents where a Finding was discovered within an asset.
 */
alias Location = SourceFileLocation;

/**
 * SourceFileLocation represents a source file location within an asset where a
 * Finding was discovered.
 */
union SourceFileLocation {
    entireFile: SourceFilePath,
    singleLine: SourceFileLine,
    range: SourceFileRange,
}

/**
 * SourceFilePath represents an entire source file as the location of a Finding.
 */
model SourceFilePath {
    path: string;
}

/**
 * SourceFileLine represents a single line within a source code file as the
 * location of a Finding. Lines being delimited by newlines and/or carriage
 * returns in a text file.
 */
model SourceFileLine extends SourceFilePath {
    line: integer;
}

/**
 * SourceFileRange represents a range of lines or characters within a source
 * code text file as the location of a Finding.
 */
model SourceFileRange extends SourceFilePath {
    startLine: integer;
    startColumn?: integer;
    endLine: integer;
    endColumn?: integer;
}

/**
 * Vulnerability represents details about the security weakness of a Finding.
 */
model Vulnerability {

}

/**
 * Remediation contains information about how to resolve or remediate the
 * vulnerability of a Finding.
 */
model Remediation {

}
