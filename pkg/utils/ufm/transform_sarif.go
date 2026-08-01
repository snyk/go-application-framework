package ufm

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	sarif_utils "github.com/snyk/go-application-framework/pkg/utils/sarif"
)

func TransformToUFMFromSarif(sarifDoc *sarif.SarifDocument, testSummary *json_schemas.TestSummary) (testapi.TestResult, error) {
	findings, extras, err := mapUFMFindings(sarifDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to map findings: %w", err)
	}

	effectiveSummary := buildEffectiveSummary(testSummary)
	rawSummary := buildRawSummary(testSummary)
	suppressedSummary := buildSuppressedSummary(testSummary)

	result := NewSarifTestResult(
		findings,
		effectiveSummary,
		rawSummary,
		suppressedSummary,
		testSummary,
		sarifDoc,
	)

	for key, value := range extras {
		result.SetMetadata(key, value)
	}

	return result, nil
}

type SuppressionExtra struct {
	GUID       string `json:"guid,omitempty"`
	Category   string `json:"category,omitempty"`
	IgnoredBy  string `json:"ignoredBy,omitempty"`
	Email      string `json:"email,omitempty"`
	Expiration string `json:"expiration,omitempty"`
	IgnoredOn  string `json:"ignoredOn,omitempty"`
}

type PriorityScoreFactor struct {
	Label bool   `json:"label"`
	Type  string `json:"type"`
}

type FindingExtra struct {
	Fingerprints           map[string]string     `json:"fingerprints,omitempty"`
	IsAutofixable          bool                  `json:"isAutofixable,omitempty"`
	Arguments              []string              `json:"arguments,omitempty"`
	Suppression            *SuppressionExtra     `json:"suppression,omitempty"`
	MessageText            string                `json:"messageText,omitempty"`
	MessageMarkdown        string                `json:"messageMarkdown,omitempty"`
	RuleIndex              int                   `json:"ruleIndex"`
	PriorityScoreFactors   []PriorityScoreFactor `json:"priorityScoreFactors,omitempty"`
	PolicyOriginalLevel    string                `json:"policyOriginalLevel,omitempty"`
	PolicySeverity         string                `json:"policySeverity,omitempty"`
	PolicyOriginalSeverity string                `json:"policyOriginalSeverity,omitempty"`
}

func mapUFMFindings(sarifDoc *sarif.SarifDocument) ([]testapi.FindingData, map[string]interface{}, error) {
	if len(sarifDoc.Runs) == 0 {
		return []testapi.FindingData{}, nil, nil
	}

	var findings []testapi.FindingData
	rules := sarifDoc.Runs[0].Tool.Driver.Rules
	perFinding := make(map[string]interface{})

	for _, res := range sarifDoc.Runs[0].Results {
		finding, err := mapUFMFinding(res, rules)
		if err != nil {
			return nil, nil, err
		}

		findingID := finding.Id.String()
		extra := FindingExtra{
			Fingerprints:         collectFingerprints(res.Fingerprints),
			IsAutofixable:        res.Properties.IsAutofixable,
			Arguments:            res.Message.Arguments,
			MessageText:          res.Message.Text,
			MessageMarkdown:      res.Message.Markdown,
			RuleIndex:            res.RuleIndex,
			PriorityScoreFactors: collectPriorityScoreFactors(res),
		}
		if res.Properties.Policy != nil {
			extra.PolicyOriginalLevel = res.Properties.Policy.OriginalLevel
			extra.PolicySeverity = res.Properties.Policy.Severity
			extra.PolicyOriginalSeverity = res.Properties.Policy.OriginalSeverity
		}
		if len(res.Suppressions) > 0 {
			extra.Suppression = collectSuppressionDetails(res)
		}
		perFinding[findingID] = extra

		findings = append(findings, finding)
	}

	extras := map[string]interface{}{
		MetadataKeyFindingExtras: perFinding,
	}

	return findings, extras, nil
}

func mapUFMFinding(res sarif.Result, rules []sarif.Rule) (testapi.FindingData, error) {
	findingID := generateFindingID(res)
	findingType := testapi.Findings

	title := res.Message.Text
	description := res.Message.Markdown
	if description == "" {
		description = res.Message.Text
	}

	var shortDescription string
	if res.RuleIndex >= 0 && res.RuleIndex < len(rules) {
		shortDescription = rules[res.RuleIndex].ShortDescription.Text
	}
	if shortDescription != "" {
		title = shortDescription
	}

	severity := testapi.Severity(sarif_utils.SarifLevelToSeverity(res.Level))

	locations, err := mapUFMLocations(res)
	if err != nil {
		return testapi.FindingData{}, fmt.Errorf("failed to map locations: %w", err)
	}

	key := res.Fingerprints.Identity
	if key == "" {
		key = res.Fingerprints.Num0
	}
	if key == "" {
		key = res.RuleID
	}

	problems := mapUFMProblems(res, rules)
	if codeRuleProblem := mapSnykCodeRuleProblem(res, rules); codeRuleProblem != nil {
		problems = append([]testapi.Problem{*codeRuleProblem}, problems...)
	}

	evidence := mapUFMEvidence(res)
	risk := mapUFMRisk(res)
	policyMods := mapUFMPolicyModifications(res)

	finding := testapi.FindingData{
		Id:   &findingID,
		Type: &findingType,
		Attributes: &testapi.FindingAttributes{
			Title:               title,
			Description:         description,
			FindingType:         testapi.FindingTypeSast,
			Key:                 key,
			Rating:              testapi.Rating{Severity: severity},
			Risk:                risk,
			Locations:           locations,
			Problems:            problems,
			Evidence:            evidence,
			PolicyModifications: policyMods,
		},
	}

	suppression := mapUFMSuppression(res)
	if suppression != nil {
		finding.Attributes.Suppression = suppression
	}

	return finding, nil
}

func generateFindingID(res sarif.Result) uuid.UUID {
	if res.Fingerprints.Identity != "" {
		id, err := uuid.Parse(res.Fingerprints.Identity)
		if err == nil {
			return id
		}
	}

	seed := res.RuleID + res.Fingerprints.Num0 + res.Fingerprints.Num1
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(seed))
}

func mapUFMLocations(res sarif.Result) ([]testapi.FindingLocation, error) {
	locations := make([]testapi.FindingLocation, 0, len(res.Locations))
	for _, loc := range res.Locations {
		pl := loc.PhysicalLocation
		srcLoc := testapi.SourceLocation{
			FilePath:   pl.ArtifactLocation.URI,
			FromLine:   pl.Region.StartLine,
			FromColumn: intPtr(pl.Region.StartColumn),
			ToLine:     intPtr(pl.Region.EndLine),
			ToColumn:   intPtr(pl.Region.EndColumn),
		}

		var fl testapi.FindingLocation
		if err := fl.FromSourceLocation(srcLoc); err != nil {
			return nil, fmt.Errorf("failed to create source location: %w", err)
		}
		locations = append(locations, fl)
	}
	return locations, nil
}

func mapUFMProblems(res sarif.Result, rules []sarif.Rule) []testapi.Problem {
	if res.RuleIndex < 0 || res.RuleIndex >= len(rules) {
		return []testapi.Problem{}
	}
	rule := rules[res.RuleIndex]
	var problems []testapi.Problem
	for _, cwe := range rule.Properties.Cwe {
		var p testapi.Problem
		cweP := testapi.CweProblem{
			Id:     cwe,
			Source: testapi.Cwe,
		}
		if err := p.FromCweProblem(cweP); err == nil {
			problems = append(problems, p)
		}
	}
	return problems
}

func mapSnykCodeRuleProblem(res sarif.Result, rules []sarif.Rule) *testapi.Problem {
	if res.RuleIndex < 0 || res.RuleIndex >= len(rules) {
		return nil
	}
	rule := rules[res.RuleIndex]

	codeRule := testapi.SnykCodeRuleProblem{
		Id:     rule.ID,
		Name:   rule.Name,
		Source: testapi.SnykCodeRule,
		DefaultConfiguration: testapi.SnykcoderuleConfiguration{
			Severity: testapi.Severity(sarif_utils.SarifLevelToSeverity(rule.DefaultConfiguration.Level)),
		},
		Help: testapi.SnykcoderuleMultiformatMessageString{
			Text:     strPtr(rule.Help.Text),
			Markdown: strPtr(rule.Help.Markdown),
		},
		ShortDescription: testapi.SnykcoderuleMultiformatMessageString{
			Text: strPtr(rule.ShortDescription.Text),
		},
		Properties: testapi.SnykcoderuleProperties{
			Categories:                rule.Properties.Categories,
			Cwe:                       rule.Properties.Cwe,
			Precision:                 rule.Properties.Precision,
			RepoDatasetSize:           uint32(rule.Properties.RepoDatasetSize),
			ExampleCommitDescriptions: rule.Properties.ExampleCommitDescriptions,
			ExampleCommitFixes:        mapExampleCommitFixes(rule.Properties.ExampleCommitFixes),
			Tags:                      rule.Properties.Tags,
		},
	}

	var p testapi.Problem
	if err := p.FromSnykCodeRuleProblem(codeRule); err != nil {
		return nil
	}
	return &p
}

func mapExampleCommitFixes(fixes []sarif.ExampleCommitFix) []testapi.SnykcoderuleExampleCommitFix {
	result := make([]testapi.SnykcoderuleExampleCommitFix, 0, len(fixes))
	for _, fix := range fixes {
		ufmFix := testapi.SnykcoderuleExampleCommitFix{
			CommitUrl: fix.CommitURL,
			Lines:     make([]testapi.SnykcoderuleExampleCommitChange, 0, len(fix.Lines)),
		}
		for _, line := range fix.Lines {
			ufmFix.Lines = append(ufmFix.Lines, testapi.SnykcoderuleExampleCommitChange{
				Line:       line.Line,
				LineNumber: uint32(line.LineNumber),
				LineChange: line.LineChange,
			})
		}
		result = append(result, ufmFix)
	}
	return result
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func mapUFMEvidence(res sarif.Result) []testapi.Evidence {
	var evidence []testapi.Evidence
	for _, cf := range res.CodeFlows {
		for _, tf := range cf.ThreadFlows {
			flow := make([]testapi.FileRegion, 0, len(tf.Locations))
			for _, loc := range tf.Locations {
				pl := loc.Location.PhysicalLocation
				flow = append(flow, testapi.FileRegion{
					FilePath:   pl.ArtifactLocation.URI,
					FromLine:   pl.Region.StartLine,
					FromColumn: intPtr(pl.Region.StartColumn),
					ToLine:     intPtr(pl.Region.EndLine),
					ToColumn:   intPtr(pl.Region.EndColumn),
				})
			}
			if len(flow) > 0 {
				execFlow := testapi.ExecutionFlowEvidence{
					Flow:   flow,
					Source: testapi.ExecutionFlow,
				}
				var ev testapi.Evidence
				if err := ev.FromExecutionFlowEvidence(execFlow); err == nil {
					evidence = append(evidence, ev)
				}
			}
		}
	}
	if evidence == nil {
		return []testapi.Evidence{}
	}
	return evidence
}

func mapUFMRisk(res sarif.Result) testapi.Risk {
	if res.Properties.PriorityScore <= 0 {
		return testapi.Risk{}
	}
	return testapi.Risk{
		RiskScore: &testapi.RiskScore{
			Value: uint16(res.Properties.PriorityScore),
		},
	}
}

func mapUFMPolicyModifications(res sarif.Result) *[]testapi.PolicyModification {
	if res.Properties.Policy == nil {
		return nil
	}
	policy := res.Properties.Policy
	originalSeverity := sarif_utils.SarifLevelToSeverity(policy.OriginalLevel)
	var prior interface{} = testapi.Severity(originalSeverity)

	return &[]testapi.PolicyModification{
		{
			Pointer: "/rating/severity",
			Prior:   &prior,
			Reason:  fmt.Sprintf("Org policy changed severity from %s to %s", policy.OriginalSeverity, policy.Severity),
		},
	}
}

func collectSuppressionDetails(res sarif.Result) *SuppressionExtra {
	suppression, _ := sarif_utils.GetHighestSuppression(res.Suppressions)
	if suppression == nil {
		return nil
	}

	extra := &SuppressionExtra{
		GUID:      suppression.Guid,
		Category:  string(suppression.Properties.Category),
		IgnoredBy: suppression.Properties.IgnoredBy.Name,
		IgnoredOn: suppression.Properties.IgnoredOn,
	}
	if suppression.Properties.IgnoredBy.Email != nil {
		extra.Email = *suppression.Properties.IgnoredBy.Email
	}
	if suppression.Properties.Expiration != nil {
		extra.Expiration = *suppression.Properties.Expiration
	}
	return extra
}

func mapUFMSuppression(res sarif.Result) *testapi.Suppression {
	suppression, status := sarif_utils.GetHighestSuppression(res.Suppressions)
	if suppression == nil {
		return nil
	}

	ufmSuppression := &testapi.Suppression{
		Justification: &suppression.Justification,
	}

	switch status {
	case sarif.Accepted:
		ufmSuppression.Status = testapi.SuppressionStatusIgnored
	case sarif.UnderReview:
		ufmSuppression.Status = testapi.SuppressionStatusPendingIgnoreApproval
	case sarif.Rejected:
		ufmSuppression.Status = testapi.SuppressionStatusOther
	default:
		ufmSuppression.Status = testapi.SuppressionStatusIgnored
	}

	if suppression.Properties.IgnoredOn != "" {
		if t, err := time.Parse(time.RFC3339, suppression.Properties.IgnoredOn); err == nil {
			ufmSuppression.CreatedAt = &t
		}
	}

	if suppression.Properties.Expiration != nil {
		if t, err := time.Parse(time.RFC3339, *suppression.Properties.Expiration); err == nil {
			ufmSuppression.ExpiresAt = &t
		}
	}

	return ufmSuppression
}

func buildEffectiveSummary(testSummary *json_schemas.TestSummary) *testapi.FindingSummary {
	if testSummary == nil {
		return nil
	}

	countBy := make(map[string]map[string]uint32)
	severityCounts := make(map[string]uint32)
	var total uint32

	for _, result := range testSummary.Results {
		severityCounts[result.Severity] = uint32(result.Open)
		total += uint32(result.Open)
	}

	countBy["severity"] = severityCounts

	return &testapi.FindingSummary{
		Count:   total,
		CountBy: &countBy,
	}
}

func buildRawSummary(testSummary *json_schemas.TestSummary) *testapi.FindingSummary {
	if testSummary == nil {
		return nil
	}

	countBy := make(map[string]map[string]uint32)
	severityCounts := make(map[string]uint32)
	var total uint32

	for _, result := range testSummary.Results {
		severityCounts[result.Severity] = uint32(result.Total)
		total += uint32(result.Total)
	}

	countBy["severity"] = severityCounts

	return &testapi.FindingSummary{
		Count:   total,
		CountBy: &countBy,
	}
}

func buildSuppressedSummary(testSummary *json_schemas.TestSummary) *testapi.FindingSummary {
	if testSummary == nil {
		return nil
	}

	countBy := make(map[string]map[string]uint32)
	severityCounts := make(map[string]uint32)
	var total uint32

	for _, result := range testSummary.Results {
		severityCounts[result.Severity] = uint32(result.Ignored)
		total += uint32(result.Ignored)
	}

	countBy["severity"] = severityCounts

	return &testapi.FindingSummary{
		Count:   total,
		CountBy: &countBy,
	}
}

func collectPriorityScoreFactors(res sarif.Result) []PriorityScoreFactor {
	if len(res.Properties.PriorityScoreFactors) == 0 {
		return nil
	}
	factors := make([]PriorityScoreFactor, 0, len(res.Properties.PriorityScoreFactors))
	for _, f := range res.Properties.PriorityScoreFactors {
		factors = append(factors, PriorityScoreFactor{
			Label: f.Label,
			Type:  f.Type,
		})
	}
	return factors
}

func collectFingerprints(fp sarif.Fingerprints) map[string]string {
	m := make(map[string]string)
	if fp.Identity != "" {
		m["identity"] = fp.Identity
	}
	if fp.Num0 != "" {
		m["0"] = fp.Num0
	}
	if fp.Num1 != "" {
		m["1"] = fp.Num1
	}
	if fp.SnykAssetFindingV1 != "" {
		m["snyk/asset/finding/v1"] = fp.SnykAssetFindingV1
	}
	if fp.SnykOrgProjectFindingV1 != "" {
		m["snyk/org/project/finding/v1"] = fp.SnykOrgProjectFindingV1
	}
	return m
}

func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

const (
	MetadataKeyReportURL  = "report-url"
	MetadataKeyProjectID  = "projectid"
	MetadataKeySnapshotID = "snapshotid"
)

func TranslateMetadataToTestResult(resultMetaData *scan.ResultMetaData, result testapi.TestResult, config configuration.Configuration) {
	if resultMetaData == nil || result == nil {
		return
	}

	if len(resultMetaData.WebUiUrl) > 0 {
		result.SetMetadata(MetadataKeyReportURL, fmt.Sprintf("%s%s", config.GetString(configuration.WEB_APP_URL), resultMetaData.WebUiUrl))
	}

	if len(resultMetaData.ProjectId) > 0 {
		result.SetMetadata(MetadataKeyProjectID, resultMetaData.ProjectId)
	}

	if len(resultMetaData.SnapshotId) > 0 {
		result.SetMetadata(MetadataKeySnapshotID, resultMetaData.SnapshotId)
	}
}
