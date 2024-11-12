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
// Content address whence source code can be obtained for
// scanning.
#ContentAddress: #SchemaMap["types.LegacyDeepcodeBundleAddress"] | #SchemaMap["types.WorkspaceV1Address"]

// CreateExcludeRule defines individual rules for exclusion of
// files during a test.
// Currently it supports either bare strings as recursive globs,
// or explicitly
// stated file patterns as recursive globs.
#CreateExcludeRule:       string | #CreateObjectExcludeRule
#CreateObjectExcludeRule: #SchemaMap["types.FileObjectExcludeRule"]

// ExcludeRule defines individual rules for exclusion of files
// during a test.
// Currently it supports either bare strings as recursive globs,
// or explicitly
// stated file patterns as recursive globs.
#ExcludeRule:       string | #ObjectExcludeRule
#Fingerprint:       #SchemaMap["types.CodeSastFingerprintV0"] | #SchemaMap["types.CodeSastFingerprintV1"] | #SchemaMap["types.ScaProblemFingerprint"] | #SchemaMap["types.IdentityFingerprint"]
#LinkProperty:      #SchemaMap["io.snyk.api.common.LinkString"] | #SchemaMap["io.snyk.api.common.LinkObject"]
#ObjectExcludeRule: #SchemaMap["types.FileObjectExcludeRule"] | #SchemaMap["types.OtherObjectExcludeRule"]

// A Package is either a Package URL (pURL) or a decomposed
// PackageObject
// identifying a software package.
//
// See https://github.com/package-url/purl-spec for more
// information about
// pURLs.
#Package:     #SchemaMap["types.PackageURL"] | #SchemaMap["types.PackageObject"]
#RiskFactors: #SchemaMap["types.BusinessCriticalityRiskFactor"] | #SchemaMap["types.CvssRiskFactor"] | #SchemaMap["types.EpssRiskFactor"] | #SchemaMap["types.VulnerabilityFactRiskFactor"] | #SchemaMap["types.VulnerabilityInstanceFactRiskFactor"]

// Suggestions are indications given to the user that might help
// with
// mitigating the finding.
#Suggestion: #SchemaMap["types.SuggestedPackageUpgrade"] | #SchemaMap["types.SuggestedOther"]

// TestInput defines what will be tested.
//
// Another term for this might be "test coordinates".
#TestInput: #SchemaMap["types.GitSCMInput"] | #SchemaMap["types.ContentAddressInput"]
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
#SchemaMap: {
	"io.snyk.reactive.FindingLocation": {
		source_locations?: #SchemaMap["io.snyk.reactive.FindingSourceLocation"]
		dependency_path?: [...#SchemaMap["io.snyk.reactive.ScaPackage"]]
		...
	}
}
#SchemaMap: {
	// Original locations are necessary for "existing" and "removed"
	// findings. Locations should be available for all scan types
	// where possible.
	"io.snyk.reactive.FindingSourceLocation": {
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
}
#SchemaMap: {
	"io.snyk.reactive.ScaPackage": {
		package_name!:    string
		package_version!: string
		...
	}
}
#SchemaMap: {
	"types.BusinessCriticalityRiskFactor": {
		factor!: "business-criticality"
		value!:  "low" | "medium" | "high"
		...
	}
}
#SchemaMap: {
	"types.CodeFlow": {
		threadFlows!: [...#SchemaMap["types.ThreadFlow"]]
		...
	}
}
#SchemaMap: {
	"types.CodeSastFingerprintV0": {
		scheme!: "code-sast-v0"
		value!:  string
		...
	}
}
#SchemaMap: {
	"types.CodeSastFingerprintV1": {
		scheme!: "code-sast-v1"
		value!:  string
		...
	}
}
#SchemaMap: {
	// A Component (as in, software component) is the subject of a
	// security scan.
	"types.Component": {
		// Name of the component. Names are free-form and semantically
		// meaningful in the context of
		// what is being scanned, and how it is being scanned. It may or
		// may not be a file name or path,
		// depending on what is scanned.
		name!: string

		// Scan type of the component.
		scan_type!: #SchemaMap["types.ScanType"]
		...
	}
}
#SchemaMap: {
	// Test input obtained from a source code image, addressed by its
	// content digest.
	"types.ContentAddressInput": {
		type!: "content-address"
		spec!: #SchemaMap["types.ContentAddressSpec"]
		...
	}
}
#SchemaMap: {
	// Content address specification, which defines the target address
	// to test, or a
	// pair of addresses to test for a differential test.
	"types.ContentAddressSpec": {
		// Target content to be scanned for this security test.
		target!: #ContentAddress

		// Base content for a differential test. When provided,
		// FindingAttributes.delta will be set with respect to the base in
		// results.
		//
		// Otherwise FindingAttributes.delta is left unset.
		base?: #ContentAddress
		...
	}
}
#SchemaMap: {
	// Attributes provided when creating a new test.
	"types.CreateTestAttributes": {
		// Test inputs; what will be tested.
		input!: #TestInput

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
		context?: #SchemaMap["types.CreateTestContext"]

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
		options?: #SchemaMap["types.CreateTestOptions"]
		...
	}
}
#SchemaMap: {
	// CreateTestContext identifies the context in which this Test
	// occurs.
	"types.CreateTestContext": {
		// Indicate at which point in the SDLC lifecycle the test was
		// executed.
		sdlc_stage!: "dev" | "cicd" | "prcheck" | "recurring"

		// Git SCM URL associated with the content, if known.
		//
		// This allows providing the Git SCM URL as context in cases where
		// the input
		// is not directly imported from a Git SCM repository.
		//
		// For example, a developer working in an IDE on source code which
		// was cloned
		// from, and will be proposed for merging back into, an SCM
		// repository.
		git_scm_url?: string

		// Git SCM branch associated with the content, if known.
		//
		// This allows providing the Git SCM branch as context in cases
		// where the input
		// is not directly imported from a Git SCM repository.
		//
		// For example, a developer working in an IDE on a feature branch.
		git_scm_branch?: string
		...
	}
}
#SchemaMap: {
	// CreateTestOptions defines options which determine how the Test
	// is conducted.
	"types.CreateTestOptions": {
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
}
#SchemaMap: {
	"types.CvssRiskFactor": {
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
}
#SchemaMap: {
	"types.EpssRiskFactor": {
		factor!: "epss"
		value!:  number
		...
	}
}
#SchemaMap: {
	"types.FileObjectExcludeRule": {
		type!: "file"

		// A recursive glob matching files. Equivalent to a bare string.
		value!: string
		...
	}
}
#SchemaMap: {
	// A Finding entity with a common format for all types of security
	// scans. Notably, this is a sub-resource of a Test.
	"types.FindingAttributes": {
		// Natural key, or fingerprint, to identify the same Finding
		// across multiple
		// Test runs. Unique per Test. Here's why:
		// https://github.com/snyk/pr-experience-poc/blob/main/docs/design-documents/pr-inline-comments.md#why-do-we-need-fingerprints
		fingerprint!: [...#Fingerprint]

		// Component in which the finding was discovered.
		component!: #SchemaMap["types.Component"]

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
		locations?: [...#SchemaMap["io.snyk.reactive.FindingLocation"]]

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
			header!: strings.MaxRunes(100)

			// Full text description of the finding rule.
			//
			// Mapped from `sarif.Runs.Results.Message.Text`.
			text!: strings.MaxRunes(2000)

			// Markdown description of the finding rule.
			//
			// Mapped from `sarif.Runs.Results.Message.Markdown`.
			markdown!: strings.MaxRunes(2000)

			// Arguments to the finding rule.
			//
			// Mapped from `sarif.Runs.Results.Message.Arguments`.
			arguments!: list.MaxItems(20) & [...string]
			...
		}
		rating?:      #SchemaMap["types.FindingRating"]
		suppression?: #SchemaMap["types.Suppression"]
		codeFlows?: [...#SchemaMap["types.CodeFlow"]]
		referenceId?: #SchemaMap["types.ReferenceId"]
		...
	}
}
#SchemaMap: {
	"types.FindingCounts": #SchemaMap["io.snyk.api.common.CollectionCounts"] & {
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
}
#SchemaMap: {
	"types.FindingIdParam": {
		// The finding identity (fingerprint). Uniquely identified in
		// combination with a Test ID.
		finding_id!: string
		...
	}
}
#SchemaMap: {
	// The severity and risk rating of the vulnerability
	"types.FindingRating": {
		risk?: #SchemaMap["types.FindingRisk"]

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
}
#SchemaMap: {
	// Resources which may relate to a Finding.
	"types.FindingRelationships": {
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
}
#SchemaMap: {
	// FindingResource models a JSON API Finding resource.
	"types.FindingResource": {
		// Unique identity of this Finding instance.
		id!:            string
		type!:          "findings"
		attributes!:    #SchemaMap["types.FindingAttributes"]
		relationships!: #SchemaMap["types.FindingRelationships"]
		...
	}
}
#SchemaMap: {
	"types.FindingRisk": {
		score!:   int & >=0 & <=1000
		factors!: #RiskFactors
		...
	}
}
#SchemaMap: {
	// Summary statistics about a Test's Findings.
	"types.FindingsSummary": {
		counts!: #SchemaMap["types.FindingCounts"]
		...
	}
}
#SchemaMap: {
	// Git commit SHA.
	"types.GitCommit": strings.MinRunes(40) & =~"[0-9a-f]+"
}
#SchemaMap: {
	// Test input obtained from a Git SCM.
	"types.GitSCMInput": {
		type!: "git-scm"
		spec!: #SchemaMap["types.GitScmImportSpec"]
		...
	}
}
#SchemaMap: {
	// Git SCM import specification, which defines how to import
	// content from a Git
	// SCM repository location into a workspace for testing, or a set
	// of workspaces
	// for differential testing.
	"types.GitScmImportSpec": {
		// Git SCM repository URL.
		remote_url!: string

		// branch is optional. If not provided, the default branch is
		// used.
		branch?: string

		// base is optional. If provided, it is used in supplying
		// differential test data.
		base?: #SchemaMap["types.GitCommit"]

		// target is optional. If not provided the current HEAD of the
		// selected branch is used.
		//
		// If target is provided and branch is not, no branch metadata is
		// associated with the test.
		// If target is provided and branch is, but target is not an
		// ancestor of branch, the wrong
		// branch will be associated with a test. It is the caller's
		// responsibility to ensure this is correct.
		target?: #SchemaMap["types.GitCommit"]

		// Components that should be excluded when importing the SCM
		// contents into a Workspace.
		exclude?: [...#ExcludeRule]
		...
	}
}
#SchemaMap: {
	"types.IdentityFingerprint": {
		scheme!: "identity"
		value!:  string
		...
	}
}
#SchemaMap: {
	// Legacy Deepcode API bundle.
	//
	// This is provided provisionally for compatibility purposes.
	"types.LegacyDeepcodeBundleAddress": {
		scheme!: "deepcode-bundle"

		// Legacy Deepcode bundle ID is a sha256 sum (64 hex digits).
		bundle_id!: =~"[0-9a-f]{64}"
		...
	}
}
#SchemaMap: {
	// OtherObjectExcludeRule is a placeholder expansion value, for
	// when types of exclusion rules
	// were used in testing that are not present in the called version
	// of the API.
	"types.OtherObjectExcludeRule": {
		type!: "other"
		{[!~"^(type)$"]: _}
	}
}
#SchemaMap: {
	// PackageObject represents a decomposed Package URL, enriched
	// with a resolved
	// package repository root location. This disambiguates public
	// packages from
	// private packages in security SCA and remediation.
	"types.PackageObject": {
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
}
#SchemaMap: {
	// Package information represented in Package URL (pURL) form.
	"types.PackageURL": string
}
#SchemaMap: {
	"types.ReferenceId": {
		identifier!: string
		index!:      int
		...
	}
}
#SchemaMap: {
	// Based on Sarif rules
	"types.Rules": {
		id!:   string
		name!: string
		shortDescription!: {
			text!: string
			...
		}
		defaultConfiguration!: {
			level!: string
			...
		}
		help!: {
			markdown!: string
			text!:     string
			...
		}
		properties!: {
			tags!: [...string]
			categories!: [...string]
			exampleCommitDescriptions!: [...string]
			precision!:       string
			repoDatasetSize!: int
			cwe!: [...string]
			...
		}
		...
	}
}
#SchemaMap: {
	"types.ScaProblemFingerprint": {
		scheme!: "sca-problem"
		value!:  string
		...
	}
}
#SchemaMap: {
	// Security scan type. The scan type determines what types of
	// attributes one
	// might expect to find in the finding.
	"types.ScanType": "sca" | "sast" | "other"
}
#SchemaMap: {
	// SuggestedOther that aren't yet defined in this API version.
	"types.SuggestedOther": {
		type!: "other"
		{[!~"^(type)$"]: _}
	}
}
#SchemaMap: {
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
	"types.SuggestedPackageUpgrade": {
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
}
#SchemaMap: {
	// Reasons for why a Finding can be suppressed from a Test result.
	// This MAY NOT be required at all, given the presentation
	"types.Suppression": {
		kind!:          "ignored" | "pending_ignore_approval" | "other"
		justification?: string
		details?:       #SchemaMap["types.SuppressionDetails"]
		...
	}
}
#SchemaMap: {
	// Suppression meta data
	"types.SuppressionDetails": {
		expiration!: string
		category!:   string
		ignoredOn!:  string
		ignoredBy!:  #SchemaMap["types.User"]
		...
	}
}
#SchemaMap: {
	// TestContext identifies the context in which this Test occurs.
	"types.TestContext": {
		// Indicate at which point in the SDLC lifecycle the test was
		// executed.
		// `other` is returned if the test was created with a newer
		// version of
		// the API including a new SDLC stage, not supported in the
		// version of
		// the API used for retrieval.
		sdlc_stage!: "dev" | "cicd" | "prcheck" | "recurring" | "other"

		// Git SCM URL associated with the content, if known.
		//
		// This allows providing the Git SCM URL as context in cases where
		// the input
		// is not directly imported from a Git SCM repository.
		//
		// For example, a developer working in an IDE on source code which
		// was cloned
		// from, and will be proposed for merging back into, an SCM
		// repository.
		git_scm_url?: string

		// Git SCM branch associated with the content, if known.
		//
		// This allows providing the Git SCM branch as context in cases
		// where the input
		// is not directly imported from a Git SCM repository.
		//
		// For example, a developer working in an IDE on a feature branch.
		git_scm_branch?: string
		...
	}
}
#SchemaMap: {
	// An error that occurred during a Test.
	"types.TestError": {
		// Error code, references Snyk error catalog.
		code!: string

		// Descriptive reason for the error.
		reason?: string

		// Links to error detail information.
		links?: #SchemaMap["io.snyk.api.common.ErrorLink"]

		// Free-form metadata associated with the error.
		meta?: #SchemaMap["io.snyk.api.common.Meta"]
		...
	}
}
#SchemaMap: {
	"types.TestExecStatus": "pending" | "running" | "done"
}
#SchemaMap: {
	// TestOptions defines options which determine how the Test is
	// conducted.
	// In includes the fields used in create test options, but in a
	// backwards compatible manner.
	"types.TestOptions": {
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
}
#SchemaMap: {
	// The outcome of a Test; pass or fail. It is possible for the
	// Test to show
	// failure before the overall status has completed.
	"types.TestOutcome": {
		result!: "pass" | "fail"
		reason?: "policy_breach" | "timeout" | "other"
		...
	}
}
#SchemaMap: {
	// Resources related to a test.
	"types.TestRelationships": {
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
}
#SchemaMap: {
	// TestResource models a JSON API Test resource.
	"types.TestResource": {
		// Test resource ID. A unique ID assigned to each created test.
		id!: string

		// Test resource type.
		type!: "tests"

		// Summary-level attributes of a test.
		attributes!: {
			// State of the test, which should be polled to status "running"
			// or "done"
			// before unmarshaling into this type.
			state!: #SchemaMap["types.TestState"]

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
			context?: #SchemaMap["types.TestContext"]

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
			options?: #SchemaMap["types.TestOptions"]

			// Overall outcome of the security test: pass or fail.
			//
			// This outcome may indicate failure early even while the test is
			// still
			// running to completion.
			outcome!: #SchemaMap["types.TestOutcome"]

			// Summary of all the findings discovered by all the security
			// scans conducted
			// for this test.
			summary!: #SchemaMap["types.FindingsSummary"]
			...
		}
		relationships!: #SchemaMap["types.TestRelationships"]
		...
	}
}
#SchemaMap: {
	// The state of a Test execution. Does not include the pass or
	// fail.
	"types.TestState": {
		// Test execution status.
		status!: #SchemaMap["types.TestExecStatus"]

		// Errors that occurred during the test execution.
		errors?: #SchemaMap["types.TestError"]
		...
	}
}
#SchemaMap: {
	"types.ThreadFlow": {
		locations!: [...#SchemaMap["io.snyk.reactive.FindingSourceLocation"]]
		...
	}
}
#SchemaMap: {
	// User definition
	"types.User": {
		name!:  string
		email!: string
		...
	}
}
#SchemaMap: {
	"types.VulnerabilityFactRiskFactor": {
		factor!: "vulnerability-fact"
		name!:   string
		value!:  bool
		...
	}
}
#SchemaMap: {
	"types.VulnerabilityInstanceFactRiskFactor": {
		factor!: "vulnerability-instance-fact"
		name!:   string
		value!:  bool
		...
	}
}
#SchemaMap: {
	// Workspace v1 content storage address.
	//
	// TODO: Update this as needed.
	"types.WorkspaceV1Address": {
		scheme!: "workspace-v1"

		// Workspace v1 is a sha256 sum (64 hex digits).
		workspace_id!: =~"[0-9a-f]{64}"
		...
	}
}
