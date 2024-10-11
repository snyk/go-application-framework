// Legacy Test Dependency Graph API
//
// The Snyk Test API to run, re-run, list, fetch, or cancel any
// supported test
// at Snyk.
package v1_test_dep_graph

info: {
	title:   *"Legacy Test Dependency Graph API" | string
	version: *"v1" | string
	description: """
		The Snyk Test API to run, re-run, list, fetch, or cancel any supported test
		at Snyk.
		"""
}

#AffectedPackage: {
	pkg!: #Package
	issues!: [string]: #Issue
	{[!~"^(pkg|issues)$"]: _}
}
#CvssDetails: {
	assigner?:         string
	severity?:         #Severity
	cvssV3Vector?:     string
	cvssV3BaseScore?:  number
	modificationTime?: #rfc3339Microseconds
	{[!~"^(assigner|severity|cvssV3Vector|cvssV3BaseScore|modificationTime)$"]: _}
}
#CvssSource: {
	type?:             string
	vector?:           string
	assigner?:         string
	severity?:         #Severity
	baseScore?:        number
	cvssVersion?:      string
	modificationTime!: #rfc3339Microseconds
	{[!~"^(type|vector|assigner|severity|baseScore|cvssVersion|modificationTime)$"]: _}
}
#EpssDetails: {
	percentile?:   string
	probability?:  string
	modelVersion?: string
	{[!~"^(percentile|probability|modelVersion)$"]: _}
}
#ExploitDetails: {
	sources?: [...]
	maturityLevels?: [...#MaturityLevel]
	{[!~"^(sources|maturityLevels)$"]: _}
}
#FixInfo: {
	isPatchable!: bool
	upgradePaths!: [...#UpgradePath]
	isRuntime?:  bool
	isPinnable?: bool
	{[!~"^(isPatchable|upgradePaths|isRuntime|isPinnable)$"]: _}
}
#IgnoreSettings: {
	adminOnly!:                  bool
	reasonRequired!:             bool
	disregardFilesystemIgnores!: bool
	{[!~"^(adminOnly|reasonRequired|disregardFilesystemIgnores)$"]: _}
}
#Issue: {
	issueId!: string
	fixInfo!: #FixInfo
	{[!~"^(issueId|fixInfo)$"]: _}
}
#IssueData: {
	id!:     string
	title!:  string
	CVSSv3?: string
	credit?: [...string]
	semver!: {
		// Ranges of vulnerable versions
		vulnerable!: [...string]
		...
	}
	exploit?: string

	// List of versions in which the vulnerability is fixed.
	//
	// TODO: can this be a range too?
	fixedIn!: [...string]
	patches?: [...string]
	insights?: [string]: _
	language!:  string
	severity!:  #Severity
	cvssScore!: number
	functions?: [...]
	malicious?:  bool
	isDisputed?: bool
	moduleName!: string
	references?: [...#IssueReferences]
	cvssDetails?: [...#CvssDetails]
	cvssSources?: [...#CvssSource]
	description!: string
	epssDetails?:
		null | #EpssDetails & {
			...
		}
	identifiers?:  #IssueIdentifiers
	packageName!:  string
	proprietary?:  false
	creationTime?: #rfc3339Microseconds
	functions_new?: [...]
	alternativeIds?: [...]
	disclosureTime?:       #rfc3339Microseconds
	exploitDetails?:       #ExploitDetails
	packageManager!:       string
	publicationTime?:      #rfc3339Microseconds
	severityBasedOn?:      string
	modificationTime?:     #rfc3339Microseconds
	socialTrendAlert?:     bool
	severityWithCritical!: #Severity
	name?:                 string
	version?:              string
	from?: [...string]
	{[!~"^(id|title|CVSSv3|credit|semver|exploit|fixedIn|patches|insights|language|severity|cvssScore|functions|malicious|isDisputed|moduleName|references|cvssDetails|cvssSources|description|epssDetails|identifiers|packageName|proprietary|creationTime|functions_new|alternativeIds|disclosureTime|exploitDetails|packageManager|publicationTime|severityBasedOn|modificationTime|socialTrendAlert|severityWithCritical|name|version|from)$"]: _}
}
#IssueIdentifiers: {
	CVE?: [...string]
	CWE?: [...string]
	{[!~"^(CVE|CWE)$"]: _}
}
#IssueReferences: {
	url!:   string
	title?: string
	{[!~"^(url|title)$"]: _}
}
#LicenseSeverity: {
	licenseType!:  string
	severity!:     #Severity
	instructions!: string
	{[!~"^(licenseType|severity|instructions)$"]: _}
}
#LicensesPolicy: {
	severities!: [string]:      _
	orgLicenseRules!: [string]: #LicenseSeverity
	{[!~"^(severities|orgLicenseRules)$"]: _}
}
#MaturityLevel: {
	type?:   string
	level?:  string
	format?: string
	{[!~"^(type|level|format)$"]: _}
}
#Meta: {
	isPrivate!:         bool
	isLicensesEnabled!: bool
	projectId!:         string
	policy!:            string
	ignoreSettings!:    #IgnoreSettings
	org!:               string
	licensesPolicy!:    #LicensesPolicy
	{[!~"^(isPrivate|isLicensesEnabled|projectId|policy|ignoreSettings|org|licensesPolicy)$"]: _}
}
#Package: {
	name!:    string
	version!: string
	{[!~"^(name|version)$"]: _}
}
#PackageUpgrade: #Package & {
	...
} & {
	newVersion!: string
	{[!~"^(newVersion)$"]: _}
}
#PatchObject: {
	patched!: string
	{[!~"^(patched)$"]: _}
}
#PatchRemediation: {
	paths!: [...{
		[string]: #PatchObject
	}]
	{[!~"^(paths)$"]: _}
}
#Remediation: {
	unresolved!: [...#IssueData]
	upgrade!: [string]: #UpgradePackage
	patch!: [string]:   #PatchRemediation
	ignore!: [string]:  _
	pin!: [string]:     #UpgradePackage
	{[!~"^(unresolved|upgrade|patch|ignore|pin)$"]: _}
}
#ResponseBody: {
	result!: #Result
	meta!:   #Meta
	{[!~"^(result|meta)$"]: _}
}
#Result: {
	affectedPkgs!: [string]: #AffectedPackage
	issuesData!: [string]:   #IssueData
	remediation!: #Remediation
	{[!~"^(affectedPkgs|issuesData|remediation)$"]: _}
}
#Severity: "none" | "low" | "medium" | "high" | "critical"
#UpgradePackage: {
	upgradeTo?: string
	upgrades?: [...string]
	vulns?: [...string]
	isTransitive?: bool
	{[!~"^(upgradeTo|upgrades|vulns|isTransitive)$"]: _}
}
#UpgradePath: {
	path!: [...#PackageUpgrade]
	{[!~"^(path)$"]: _}
}

// An RFC3339 timestamp with up to microsecond resolution.
#rfc3339Microseconds: string
