// Snyk Test API
//
// The Snyk Test API to run, re-run, list, fetch, or cancel any
// supported test
// at Snyk.
package testapi

import (
	"list"
	"strings"
)

info: {
	title:   *"Snyk Test API" | string
	version: *"2024-08-06" | string
	description: """
		The Snyk Test API to run, re-run, list, fetch, or cancel any supported test
		at Snyk.
		"""
}

#BusinessCriticalityRiskFactor: {
	factor!: "business-criticality"
	value!:  "low" | "medium" | "high"
	...
}
#CodeSastFingerprintV0: {
	scheme!: "code-sast-v0"
	value!:  string
	...
}
#CodeSastFingerprintV1: {
	scheme!: "code-sast-v1"
	value!:  string
	...
}

// A Component (as in, software component) is the subject of a
// security scan.
#Component: {
	// Name of the component. Names are free-form and semantically
	// meaningful in the context of
	// what is being scanned, and how it is being scanned. It may or
	// may not be a file name or path,
	// depending on what is scanned.
	name!: string

	// Scan type of the component.
	scan_type!: #ScanType
	...
}

// CreateExcludeRule defines individual rules for exclusion of
// files during a test.
// Currently it supports either bare strings as recursive globs,
// or explicitly
// stated file patterns as recursive globs.
#CreateExcludeRule:       string | #CreateObjectExcludeRule
#CreateObjectExcludeRule: #FileObjectExcludeRule

// Attributes provided when creating a new test.
#CreateTestAttributes: {
	// Test context; pertinent information important to associate with
	// the outcome
	// of the test and its further processing, but is not directly
	// used in the
	// test.
	//
	// These are worth modeling with a concrete type, rather than as
	// generic
	// free-form metadata to communicate to consumers of the test what
	// values are
	// available.
	context?: #CreateTestContext

	// CreateTestOptions are arguments which configure the test and
	// determine the
	// behavior of how it is conducted.
	//
	// Options are optional when creating a test and may be derived
	// from other
	// sources, such as a test configuration policy if not specified.
	// Provided
	// options may be merged with or overridden by such policy.
	//
	// In the requested Test resource, these options will reflect the
	// effective
	// options resolved and applied to the execution of the test.
	options?: #CreateTestOptions
	...
}

// CreateTestContext identifies the context in which this Test
// occurs.
#CreateTestContext: {
	// Indicate at which point in the SDLC lifecycle the test was
	// executed.
	sdlc_stage!: "dev" | "cicd" | "prcheck" | "recurring"
	...
}

// CreateTestOptions defines options which determine how the Test
// is conducted.
#CreateTestOptions: {
	// Files from which findings should be excluded and removed from
	// results.
	//
	// This is different from FindingAttributes.suppressions; the
	// exclude is an
	// up-front declaration that findings in the excluded files are
	// immaterial to the test result (pass/fail), and should not be
	// reported at all.
	//
	// Excluded files might still be used to link other files/findings
	// though. For
	// example, a SAST (source-to-sink) or SCA analysis (transitive
	// dependency
	// chain) might transit an excluded file, enabling discovery in a
	// non-excluded file.
	exclude?: list.MaxItems(1024) & [...#CreateExcludeRule] & [_, ...]
	...
}
#CvssRiskFactor: {
	factor!: "cvss"

	// The CVSS version being described. This will be a published CVSS
	// specification version, such as "3.1" or "4.0"
	cvss_version!: string

	// CVSS vector string, the format of which may be CVSS
	// specification version
	// dependent.
	//
	// See
	// https://www.first.org/cvss/specification-document#Vector-String
	// for
	// details.
	vector!: string
	...
}
#EpssRiskFactor: {
	factor!: "epss"
	value!:  number
	...
}

// ExcludeRule defines individual rules for exclusion of files
// during a test.
// Currently it supports either bare strings as recursive globs,
// or explicitly
// stated file patterns as recursive globs.
#ExcludeRule: string | #ObjectExcludeRule
#FileObjectExcludeRule: {
	type!: "file"

	// A recursive glob matching files. Equivalent to a bare string.
	value!: string
	...
}

// A Finding entity with a common format for all types of security
// scans. Notably, this is a sub-resource of a Test.
#FindingAttributes: {
	// Natural key, or fingerprint, to identify the same Finding
	// across multiple
	// Test runs. Unique per Test. Here's why:
	// https://github.com/snyk/pr-experience-poc/blob/main/docs/design-documents/pr-inline-comments.md#why-do-we-need-fingerprints
	fingerprint!: #Fingerprint

	// Component in which the finding was discovered.
	component!: #Component

	// Represent whether a finding is net new (introduced), removed,
	// or preserved
	// in a test involving a diff between inputs.
	//
	// Only set in a differential test conducted with respect to base
	// content.
	delta?: "introduced" | "removed" | "existing"

	// A set of locations where the result was detected. Only one
	// location should
	// be included unless the finding can only be resolved by making a
	// change at
	// every location.
	locations?: [...#FindingLocation]

	// Suggestions are indications given to the user that might help
	// with
	// mitigating the finding.
	//
	// For mitigation with a higher degree of confidence, remediation
	// and fix
	// relationship links should be used.
	suggestions?: list.MaxItems(3) & [...#Suggestion]
	message!: {
		// Short text description of finding rule.
		//
		// Could be sourced from
		// `sarif.Runs.Tool.Driver.Rules.ShortDescription.Text`.
		header!: strings.MaxRunes(200)

		// Full text description of the finding rule.
		//
		// Mapped from `sarif.Runs.Results.Message.Text`.
		text!: strings.MaxRunes(2000)

		// Markdown description of the finding rule.
		//
		// Mapped from `sarif.Runs.Results.Message.Markdown`.
		markdown?: strings.MaxRunes(2000)

		// Arguments to the finding rule.
		//
		// Mapped from `sarif.Runs.Results.Message.Arguments`.
		arguments?: list.MaxItems(20) & [...string]
		...
	}
	rating?:      #FindingRating
	suppression?: #Suppression
	...
}
#FindingCounts: #SchemaMap["io.snyk.api.common.CollectionCounts"] & {
	...
} & {
	// Total finding counts (not considering ignores) grouped by
	// severity and
	// possibly other factors.
	count_by!: {
		severity!: [string]: int
		{[!~"^(severity)$"]: [string]: int}
	}

	// Net finding counts (ignores removed) grouped by severity and
	// possibly other
	// factors.
	count_by_adjusted!: {
		severity!: [string]: int
		{[!~"^(severity)$"]: [string]: int}
	}

	// Ordering hint for the grouping keys in count_by.
	//
	// Record key is a well-known grouping of the resource object,
	// matched with
	// count_by.
	//
	// Record values are arrays of known possible values for the group
	// keys in
	// ascending order, from lowest to highest. Values other than
	// those enumerated
	// must be tolerated; their ordering is unspecified with respect
	// to enumerated
	// values.
	count_key_order_asc!: {
		// FindingCounts has a deterministic ordering for severity counts.
		severity!: [...]
		{[!~"^(severity)$"]: [...string]}
	}

	// Findings excluded from the count shown to users, including
	// ignored findings.
	count_suppressed!: int

	// Net count of findings minus suppressions.
	count_adjusted!: int
	...
}
#FindingIdParam: {
	// The finding identity (fingerprint). Uniquely identified in
	// combination with a Test ID.
	finding_id!: string
	...
}
#FindingLocation: {
	source_locations?: #FindingSourceLocation
	dependency_path?: [...#ScaPackage]
	...
}

// The severity and risk rating of the vulnerability
#FindingRating: {
	risk?: #FindingRisk

	// A value which may be modified by enrichment stages.
	severity!: {
		// Current value.
		value!: "none" | "info" | "low" | "medium" | "high" | "critical"

		// Original value, if modified.
		original_value?: "none" | "info" | "low" | "medium" | "high" | "critical"

		// Reason for the modification, if modified.
		reason?: "manual" | "policy" | "other"
		...
	}
	severity_method!: "CVSSv2" | "CVSSv3" | "CVSSv31" | "CVSSv4" | "OWASP" | "other"

	// Optional reason for rating the vulnerability like this
	justification?: string
	...
}

// Resources which may relate to a Finding.
#FindingRelationships: {
	// Relate to details about the component vulnerability discovered
	// in the SCA
	// finding.
	sca_vuln_details?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Relate to details about the rule which was violated in a SAST
	// finding.
	sast_rule_details?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Relate to a human-readable webpage that explains the finding,
	// if available.
	explanation?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Relate to the raw scan outputs. May be SARIF, CycloneDX+VEX or
	// other
	// scan-specific formats.
	//
	// The relationship link should point to the resource URL where
	// the raw scan
	// output can be retrieved.
	//
	// The link MAY include a URL fragment to locate the finding's
	// position within
	// the document object.
	//
	// For JSON-based MIME types, this fragment MUST be a JSON
	// Pointer.
	// For XML-based MIME types, this fragment MUST be an XPath
	// expression.
	//
	// If the fragment is specified, the fragment form MUST be
	// compatible with all
	// of the content types advertised. For example, the link MUST NOT
	// provide a JSON
	// Pointer fragment if an XML media type is advertised.
	raw_details?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta!: {
			// Content MIME types which can be used in the Accept header when
			// requesting the
			// related raw data.
			//
			// This property must not be empty, making explicit what type of
			// content
			// the API client will be receiving in the raw details resource
			// response.
			content_types!: [...string] & [_, ...]
			{[!~"^(content_types)$"]: _}
		}
		...
	}

	// Relate to fix information for the finding, if available.
	fix_details?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Relate to remediations for the finding, if available.
	remediations?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Relate to autofixes for the finding, if available.
	autofixes?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Policy modifications applied to this finding, if available.
	policy_modifications?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}
	...
}

// FindingResource models a JSON API Finding resource.
#FindingResource: {
	// Unique identity of this Finding instance.
	id!:            string
	type!:          "findings"
	attributes!:    #FindingAttributes
	relationships!: #FindingRelationships
	...
}
#FindingRisk: {
	score!:   int & >=0 & <=1000
	factors!: #RiskFactors
	...
}

// Original locations are necessary for "existing" and "removed"
// findings. Locations should be available for all scan types
// where possible.
#FindingSourceLocation: {
	// Maps
	// `sarif.Runs.Results.Location.PhysicalLocation.ArtifactLocation.URI`
	filepath!: string

	// Maps
	// `sarif.Runs.Results.Location.PhysicalLocation.Region.StartLine`
	original_start_line!: int

	// Maps
	// `sarif.Runs.Results.Location.PhysicalLocation.Region.StartColumn`
	original_start_column!: int

	// Maps
	// `sarif.Runs.Results.Location.PhysicalLocation.Region.EndLine`
	original_end_line!: int

	// Maps
	// `sarif.Runs.Results.Location.PhysicalLocation.Region.EndColumn`
	original_end_column!: int
	...
}

// Summary statistics about a Test's Findings.
#FindingsSummary: {
	counts!: #FindingCounts
	...
}
#Fingerprint:       #CodeSastFingerprintV0 | #CodeSastFingerprintV1 | #ScaProblemFingerprint
#LinkProperty:      #SchemaMap["io.snyk.api.common.LinkString"] | #SchemaMap["io.snyk.api.common.LinkObject"]
#ObjectExcludeRule: #FileObjectExcludeRule | #OtherObjectExcludeRule

// OtherObjectExludeRule is a placeholder expansion value, for
// when types of exclusion rules
// were used in testing that are not present in the called version
// of the API.
#OtherObjectExcludeRule: {
	type!: "other"
	{[!~"^(type)$"]: _}
}

// A Package is either a Package URL (pURL) or a decomposed
// PackageObject
// identifying a software package.
//
// See https://github.com/package-url/purl-spec for more
// information about
// pURLs.
#Package: #PackageURL | #PackageObject

// PackageObject represents a decomposed Package URL, enriched
// with a resolved
// package repository root location. This disambiguates public
// packages from
// private packages in security SCA and remediation.
#PackageObject: {
	// Package management system or ecosystem type.
	type!: string

	// Package management system root location.
	//
	// If set, isolates the package to a private ecosystem repository.
	//
	// Defaults to "the canonical public ecosystem repository root"
	// for the package ecosystem type.
	root?: string

	// Package name, possibly with a namespace prefix.
	name!: string

	// Package version. One would hope this is semver but this
	// generally depends
	// on the ecosystem and its package standards and requirements.
	version!: string

	// Free-form metadata about this package.
	meta?: #SchemaMap["io.snyk.api.common.Meta"]

	// Sub-package qualifier, if applicable.
	subpath?: string
	...
}

// Package information represented in Package URL (pURL) form.
#PackageURL:  string
#RiskFactors: #BusinessCriticalityRiskFactor | #CvssRiskFactor | #EpssRiskFactor | #VulnerabilityFactRiskFactor | #VulnerabilityInstanceFactRiskFactor
#ScaPackage: {
	package_name!:    string
	package_version!: string
	...
}
#ScaProblemFingerprint: {
	scheme!: "sca-problem"
	value!:  string
	...
}

// Security scan type. The scan type determines what types of
// attributes one
// might expect to find in the finding.
#ScanType: "sca" | "sast" | "other"

// SuggestedPackageUpgrade provides some basic information on how
// to mitigate an
// SCA finding in a managed package ecosystem with an upgrade.
//
// The upgrade does not take into account other dependency paths
// to the affected
// package which may have conflicting constraints. The upgrade
// version may
// introduce other vulnerabilities. This is the main difference
// between a
// suggestion and a remediation.
//
// For a comprehensive mitigation with satisfiability and security
// guarantees,
// the remediation relation should be used.
//
// If conflicts are known to exist this may be reported, but the
// absense of this
// flag should not be taken as a guarantee conflicts will not be
// encountered. It
// only means the conflict status is unknown.
#SuggestedPackageUpgrade: {
	type!: "package-upgrade"

	// Affected package.
	current_package!: #Package

	// Upgrade package in which the vulnerability is no longer
	// present.
	//
	// If unset, no upgrade version is available.
	upgrade_package?: #Package

	// Indicate whether the upgrade version is known to conflict with
	// other
	// dependencies on the same package.
	//
	// If false, the upgrade does not conflict and should be
	// applicable.
	//
	// If null or missing, conflict status is unknown or was not
	// calculated;
	// applying the upgrade could fail.
	upgrade_conflicts?:
		null | (true | false)
	...
}

// Suggestions are indications given to the user that might help
// with
// mitigating the finding.
#Suggestion: #SuggestedPackageUpgrade | #SuggestionOther
#SuggestionOther: {
	type!: "other"
	{[!~"^(type)$"]: _}
}

// Reasons for why a Finding can be suppressed from a Test result.
// This MAY NOT be required at all, given the presentation
#Suppression: {
	kind!:          "ignored" | "pending_ignore_approval" | "other"
	justification?: string
	...
}

// TestContext identifies the context in which this Test occurs.
#TestContext: {
	// Indicate at which point in the SDLC lifecycle the test was
	// executed.
	// `other` is returned if the test was created with a newer
	// version of
	// the API including a new SDLC stage, not supported in the
	// version of
	// the API used for retrieval.
	sdlc_stage!: "dev" | "cicd" | "prcheck" | "recurring" | "other"
	...
}

// TestOptions defines options which determine how the Test is
// conducted.
// In includes the fields used in create test options, but in a
// backwards compatible manner.
#TestOptions: {
	// Files from which findings should be excluded and removed from
	// results.
	//
	// This is different from FindingAttributes.suppressions; the
	// exclude is an
	// up-front declaration that findings in the excluded files are
	// immaterial to the test result (pass/fail), and should not be
	// reported at all.
	//
	// Excluded files might still be used to link other files/findings
	// though. For
	// example, a SAST (source-to-sink) or SCA analysis (transitive
	// dependency
	// chain) might transit an excluded file, enabling discovery in a
	// non-excluded file.
	exclude?: list.MaxItems(1024) & [...#ExcludeRule] & [_, ...]
	...
}

// The outcome of a Test; pass or fail. It is possible for the
// Test to show
// failure before the overall status has completed.
#TestOutcome: {
	result!: "pass" | "fail"
	reason?: "policy_breach" | "timeout" | "other"
	...
}

// Resources related to a test.
#TestRelationships: {
	// Relationship link to the findings collection for this test.
	findings!: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}

	// Relate to application-facing logs produced by the test.
	logs?: {
		data?: {
			type!: =~"^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)*$"
			id!:   string
			...
		}
		links!: #SchemaMap["io.snyk.api.common.RelatedLink"]
		meta?:  #SchemaMap["io.snyk.api.common.Meta"]
		...
	}
	...
}

// TestResource models a JSON API Test resource.
#TestResource: {
	// Test resource ID. A unique ID assigned to each created test.
	id!: string

	// Test resource type.
	type!: "tests"

	// Summary-level attributes of a test.
	attributes!: {
		// State of the test, which should be polled to status "running"
		// or "done"
		// before unmarshaling into this type.
		state!: #TestState

		// Overall outcome of the security test: pass or fail.
		//
		// This outcome may indicate failure early even while the test is
		// still
		// running to completion.
		outcome!: #TestOutcome

		// Summary of all the findings discovered by all the security
		// scans conducted
		// for this test.
		summary!: #FindingsSummary

		// Test context; pertinent information important to associate with
		// the outcome
		// of the test and its further processing, but is not directly
		// used in the
		// test.
		//
		// These are worth modeling with a concrete type, rather than as
		// generic
		// free-form metadata to communicate to consumers of the test what
		// values are
		// available.
		context?: #TestContext

		// TestOptions are arguments which were used to configure the test
		// and determine the
		// behavior of how it is conducted.
		//
		// Options are optional when creating a test and may be derived
		// from other
		// sources, such as a test configuration policy if not specified.
		// Provided
		// options may be merged with or overridden by such policy.
		//
		// In the requested Test resource, these options will reflect the
		// effective
		// options resolved and applied to the execution of the test.
		options?: #TestOptions
		...
	}
	relationships!: #TestRelationships
	...
}

// The state of a Test execution. Does not include the pass or
// fail.
#TestState: {
	...
}
#VulnerabilityFactRiskFactor: {
	factor!: "vulnerability-fact"
	name!:   string
	value!:  bool
	...
}
#VulnerabilityInstanceFactRiskFactor: {
	factor!: "vulnerability-instance-fact"
	name!:   string
	value!:  bool
	...
}
#SchemaMap: {
	// CollectionCounts implements the Snyk REST API standard
	// representation for
	// collection counts.
	//
	// Collection counts may be provided as metadata on a collection
	// resource or in
	// an attribute of a parent resource.
	//
	// See
	// https://snyk.roadie.so/docs/default/component/sweater-comb/standards/rest/#collection-counts.
	"io.snyk.api.common.CollectionCounts": {
		// Count of all items in the collection.
		count!: int

		// Counts of items grouped by various dimensions.
		//
		// Outer record key is a well-known grouping dimension of the
		// resource object.
		//
		// Inner record key is a value in that dimension.
		count_by!: {
			[string]: [string]: int
		}
		...
	}
}
#SchemaMap: {
	"io.snyk.api.common.Error": {
		// A unique identifier for this particular occurrence of the
		// problem.
		id?:    string
		links?: #SchemaMap["io.snyk.api.common.ErrorLink"]

		// The HTTP status code applicable to this problem, expressed as a
		// string value.
		status!: =~"^[45]\\\\d\\\\d$"

		// A human-readable explanation specific to this occurrence of the
		// problem.
		detail!: string

		// An application-specific error code, expressed as a string
		// value.
		code?: string

		// A short, human-readable summary of the problem that SHOULD NOT
		// change from occurrence to occurrence of the problem, except
		// for purposes of localization.
		title?: string
		source?: {
			pointer?:   string
			parameter?: string
			...
		}
		meta?: {
			...
		}
		...
	}
}
#SchemaMap: {
	"io.snyk.api.common.ErrorDocument": {
		jsonapi!: #SchemaMap["io.snyk.api.common.JsonApi"]
		errors!: [...#SchemaMap["io.snyk.api.common.Error"]] & [_, ...]
		...
	}
}
#SchemaMap: {
	// A link that leads to further details about this particular
	// occurrance of the problem.
	"io.snyk.api.common.ErrorLink": {
		about?: #LinkProperty
		{[!~"^(about)$"]: #LinkProperty}
	}
}
#SchemaMap: {
	"io.snyk.api.common.JsonApi": {
		// Version of the JSON API specification this server supports.
		version!: "1.0"
		...
	}
}
#SchemaMap: {
	"io.snyk.api.common.LinkObject": {
		href!: #SchemaMap["io.snyk.api.common.LinkString"]
		meta?: #SchemaMap["io.snyk.api.common.Meta"]
		...
	}
}
#SchemaMap: {
	"io.snyk.api.common.LinkString": string
}
#SchemaMap: {
	// Free-form object that may contain non-standard information.
	"io.snyk.api.common.Meta": {
		...
	}
}
#SchemaMap: {
	"io.snyk.api.common.PaginatedLinks": {
		first?: #LinkProperty
		last?:  #LinkProperty
		prev?:  #LinkProperty
		next?:  #LinkProperty
		self?:  #LinkProperty
		...
	}
}
#SchemaMap: {
	"io.snyk.api.common.RelatedLink": {
		related?: #LinkProperty
		...
	}
}
