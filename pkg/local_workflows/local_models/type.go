package local_models

type FindingResource TypesFindingResource
type TestOutcome TypesTestOutcome

// TODO: This schema should be imported from Dragonfly
type LocalFinding struct {
	Findings   []FindingResource    `json:"findings"`
	Outcome    TestOutcome          `json:"outcome"`
	Rules      []TypesRules         `json:"rules"`
	Summary    TypesFindingsSummary `json:"summary"`
	Links      map[string]string    `json:"links"`
	GitContext *GitContext          `json:"gitContext,omitempty"`
}

// GitContext contains git repository context information
type GitContext struct {
	RepositoryUrl string `json:"repositoryUrl,omitempty"`
	Branch        string `json:"branch,omitempty"`
	CommitHash    string `json:"commitHash,omitempty"`
}

type UnionInterface interface {
	ValueByDiscriminator() (interface{}, error)
}

const LINKS_KEY_REPORT = "report"
