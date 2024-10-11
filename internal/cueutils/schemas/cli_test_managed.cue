// CLI Managed Open Source Test
package cli_test_managed

info: {
	title:   *"CLI Managed Open Source Test" | string
	version: *"CLI" | string
}

#CvssDetail: {
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
#Filtered: {
	ignore?: [...#Vulnerability]
	patch?: [...]
	...
}
#IgnoreSettings: {
	adminOnly!:                  bool
	reasonRequired!:             bool
	disregardFilesystemIgnores!: bool
	{[!~"^(adminOnly|reasonRequired|disregardFilesystemIgnores)$"]: _}
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
#Patch: {
	id?: string
	urls?: [...string]
	version?: string
	comments?: [...string]
	modificationTime?: #rfc3339Microseconds
	{[!~"^(id|urls|version|comments|modificationTime)$"]: _}
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
	unresolved?: [...#Vulnerability]
	upgrade?: [string]: #UpgradePackage
	patch?: [string]:   #PatchRemediation
	ignore?: [string]:  _
	pin?: [string]:     #UpgradePackage
	{[!~"^(unresolved|upgrade|patch|ignore|pin)$"]: _}
}
#Result: {
	vulnerabilities!: [...#Vulnerability]
	ok!:                 bool
	dependencyCount!:    int
	org!:                string
	policy!:             string
	isPrivate!:          true
	licensesPolicy!:     #LicensesPolicy
	packageManager!:     string
	projectId!:          string
	ignoreSettings!:     #IgnoreSettings
	summary!:            string
	remediation!:        #Remediation
	filesystemPolicy!:   bool
	filtered!:           #Filtered
	uniqueCount!:        int
	projectName!:        string
	foundProjectCount!:  int
	displayTargetFile!:  string
	hasUnknownVersions!: bool
	path!:               string
	{[!~"^(vulnerabilities|ok|dependencyCount|org|policy|isPrivate|licensesPolicy|packageManager|projectId|ignoreSettings|summary|remediation|filesystemPolicy|filtered|uniqueCount|projectName|foundProjectCount|displayTargetFile|hasUnknownVersions|path)$"]: _}
}
#Severity: "none" | "low" | "medium" | "high" | "critical"
#UpgradePackage: {
	upgradeTo?: string
	upgrades?: [...string]
	vulns?: [...string]
	isTransitive?: bool
	{[!~"^(upgradeTo|upgrades|vulns|isTransitive)$"]: _}
}
#VulnIdentifiers: {
	CVE?: [...string]
	CWE?: [...string]
	{[!~"^(CVE|CWE)$"]: _}
}
#VulnReference: {
	url!:   string
	title?: string
	{[!~"^(url|title)$"]: _}
}
#Vulnerability: {
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
	patches?: [...string | #Patch]
	insights?: [string]: _
	language!:  string
	severity!:  #Severity
	cvssScore!: number
	functions?: [...]
	malicious?:  bool
	isDisputed?: bool
	moduleName!: string
	references?: [...#VulnReference]
	cvssDetails?: [...#CvssDetail]
	cvssSources?: [...#CvssSource]
	description!: string
	epssDetails?:
		null | #EpssDetails & {
			...
		}
	identifiers?:  #VulnIdentifiers
	packageName!:  string
	proprietary?:  bool
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
	from?: [...string]
	upgradePath?: [...bool | string]
	isUpgradable?: bool
	isPatchable?:  bool
	isPinnable?:   bool
	isRuntime?:    bool
	name?:         string
	version?:      string
	{[!~"^(id|title|CVSSv3|credit|semver|exploit|fixedIn|patches|insights|language|severity|cvssScore|functions|malicious|isDisputed|moduleName|references|cvssDetails|cvssSources|description|epssDetails|identifiers|packageName|proprietary|creationTime|functions_new|alternativeIds|disclosureTime|exploitDetails|packageManager|publicationTime|severityBasedOn|modificationTime|socialTrendAlert|severityWithCritical|from|upgradePath|isUpgradable|isPatchable|isPinnable|isRuntime|name|version)$"]: _}
}

// An RFC3339 timestamp with up to microsecond resolution in UTC.
#rfc3339Microseconds: string
