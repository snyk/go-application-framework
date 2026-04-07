package testapi

import "maps"

// Metadata keys for TestResult. Use with SetMetadata and GetMetadataValue for stable,
// implementation-independent access to test outcome details.
const (
	// MetadataKeyProjectID is the Snyk project UUID as a string (when present).
	MetadataKeyProjectID = "project-id"
	// MetadataKeyDependencyCount is the total dependency count from test facts when available.
	MetadataKeyDependencyCount = "dependency-count"
	// MetadataKeyDisplayTargetFile is the primary manifest / target path for dep-graph tests (first path segment).
	MetadataKeyDisplayTargetFile = "display-target-file"
	// MetadataKeyPackageManager is the package manager / ecosystem label (often set by the CLI extension).
	MetadataKeyPackageManager = "package-manager"
	// MetadataKeyProjectName is the human-readable project name (often set by the CLI extension).
	MetadataKeyProjectName = "project-name"
	// MetadataKeyTargetDirectory is the scanned target directory (often set by the CLI extension).
	MetadataKeyTargetDirectory = "target-directory"

	// MetadataKeyRawSummary is the full finding summary including suppressed findings (*FindingSummary).
	MetadataKeyRawSummary = "raw-summary"
	// MetadataKeyBreachedPolicies is the outcome breached policy set (*PolicyRefSet), when present.
	MetadataKeyBreachedPolicies = "breached-policies"
	// MetadataKeyTestResources is the test resources slice from the API response (*[]TestResource).
	MetadataKeyTestResources = "test-resources"
	// MetadataKeyTestSubject is the API test subject (*TestSubject), when present.
	MetadataKeyTestSubject = "test-subject"
	// MetadataKeySubjectLocators is the API subject locators (*[]TestSubjectLocator), when present.
	MetadataKeySubjectLocators = "subject-locators"
)

func cloneMetadataMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	return maps.Clone(m)
}

func populateCanonicalMetadata(r *testResult) {
	if r == nil {
		return
	}
	if pid := projectIDStringFromLocators(r.SubjectLocators); pid != "" {
		r.metadata[MetadataKeyProjectID] = pid
	}
	if n := dependencyCountFromFacts(r.TestFacts); n > 0 {
		r.metadata[MetadataKeyDependencyCount] = n
	}
	if path := displayTargetFileFromSubject(r.TestSubject); path != "" {
		r.metadata[MetadataKeyDisplayTargetFile] = path
	}
	if r.RawSummary != nil {
		r.metadata[MetadataKeyRawSummary] = r.RawSummary
	}
	if r.BreachedPolicies != nil {
		r.metadata[MetadataKeyBreachedPolicies] = r.BreachedPolicies
	}
	if r.TestResources != nil {
		r.metadata[MetadataKeyTestResources] = r.TestResources
	}
	if r.TestSubject != nil {
		r.metadata[MetadataKeyTestSubject] = r.TestSubject
	}
	if r.SubjectLocators != nil {
		r.metadata[MetadataKeySubjectLocators] = r.SubjectLocators
	}
}

func projectIDStringFromLocators(locators *[]TestSubjectLocator) string {
	if locators == nil {
		return ""
	}
	for _, loc := range *locators {
		disc, err := loc.Discriminator()
		if err != nil {
			continue
		}
		if disc != string(ProjectEntity) {
			continue
		}
		peLoc, err := loc.AsProjectEntityLocator()
		if err != nil {
			continue
		}
		return peLoc.ProjectId.String()
	}
	return ""
}

func dependencyCountFromFacts(facts *[]TestFact) int {
	if facts == nil {
		return 0
	}
	for _, fact := range *facts {
		if fact.Type == DependencyCountFactTypeDependencyCountFact {
			return int(fact.TotalDependencyCount)
		}
	}
	return 0
}

func displayTargetFileFromSubject(subject *TestSubject) string {
	if subject == nil {
		return ""
	}
	dg, err := subject.AsDepGraphSubject()
	if err != nil || len(dg.Locator.Paths) == 0 {
		return ""
	}
	return dg.Locator.Paths[0]
}
