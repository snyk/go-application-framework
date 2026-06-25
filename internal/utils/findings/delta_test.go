package findings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

// --- ParseChangedScope ---

func TestParseChangedScope_ValidSimple(t *testing.T) {
	input := `{"version":1,"files":{"src/app.py":[{"start":10,"end":24}]}}`
	scope, err := ParseChangedScope([]byte(input))
	require.NoError(t, err)
	assert.True(t, scope.FileInScope("src/app.py"))
	assert.False(t, scope.FileInScope("other.py"))
}

func TestParseChangedScope_AllSentinel(t *testing.T) {
	input := `{"version":1,"files":{"src/new.py":"all"}}`
	scope, err := ParseChangedScope([]byte(input))
	require.NoError(t, err)
	assert.True(t, scope.Intersects("src/new.py", 1, 9999))
}

func TestParseChangedScope_MultipleFiles(t *testing.T) {
	input := `{"version":1,"files":{"a.py":[{"start":1,"end":5}],"b.py":"all"}}`
	scope, err := ParseChangedScope([]byte(input))
	require.NoError(t, err)
	assert.True(t, scope.FileInScope("a.py"))
	assert.True(t, scope.FileInScope("b.py"))
	assert.False(t, scope.FileInScope("c.py"))
}

func TestParseChangedScope_ErrorNotJSON(t *testing.T) {
	_, err := ParseChangedScope([]byte("not json"))
	assert.Error(t, err)
}

func TestParseChangedScope_ErrorVersionMissing(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"files":{"a.py":"all"}}`))
	assert.ErrorContains(t, err, "version")
}

func TestParseChangedScope_ErrorVersionWrong(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":2,"files":{"a.py":"all"}}`))
	assert.ErrorContains(t, err, "version must be 1")
}

func TestParseChangedScope_ErrorFilesMissing(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1}`))
	assert.ErrorContains(t, err, "files")
}

func TestParseChangedScope_ErrorFilesEmpty(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1,"files":{}}`))
	assert.ErrorContains(t, err, "no files")
}

func TestParseChangedScope_ErrorNegativeLine(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1,"files":{"a.py":[{"start":-1,"end":5}]}}`))
	assert.Error(t, err)
}

func TestParseChangedScope_ErrorZeroLine(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1,"files":{"a.py":[{"start":0,"end":5}]}}`))
	assert.Error(t, err)
}

func TestParseChangedScope_ErrorStartGreaterThanEnd(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1,"files":{"a.py":[{"start":10,"end":5}]}}`))
	assert.Error(t, err)
}

func TestParseChangedScope_ErrorBadAllString(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1,"files":{"a.py":"none"}}`))
	assert.Error(t, err)
}

func TestParseChangedScope_ErrorTruncatedJSON(t *testing.T) {
	_, err := ParseChangedScope([]byte(`{"version":1,"files":{"a.py":[{"start":1`))
	assert.Error(t, err)
}

// --- NormalizeRelPath ---

func TestNormalizeRelPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"src/app.py", "src/app.py"},
		{"./src/app.py", "src/app.py"},
		{"../../src/app.py", "../../src/app.py"}, // ../ not stripped, only ./
		{"/absolute/path.py", "absolute/path.py"},
		{"src\\windows\\path.py", "src/windows/path.py"}, // backslashes always converted
		{"./", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, NormalizeRelPath(tc.input))
		})
	}
}

// --- mergeRanges ---

func TestMergeRanges(t *testing.T) {
	tests := []struct {
		name   string
		input  []Range
		output []Range
	}{
		{
			name:   "single range",
			input:  []Range{{1, 5}},
			output: []Range{{1, 5}},
		},
		{
			name:   "non-overlapping sorted",
			input:  []Range{{1, 5}, {10, 20}},
			output: []Range{{1, 5}, {10, 20}},
		},
		{
			name:   "overlapping",
			input:  []Range{{1, 10}, {8, 20}},
			output: []Range{{1, 20}},
		},
		{
			name:   "adjacent (end+1 = start)",
			input:  []Range{{1, 5}, {6, 10}},
			output: []Range{{1, 10}},
		},
		{
			name:   "unsorted input",
			input:  []Range{{10, 20}, {1, 5}},
			output: []Range{{1, 5}, {10, 20}},
		},
		{
			name:   "three overlapping into one",
			input:  []Range{{1, 10}, {5, 15}, {12, 20}},
			output: []Range{{1, 20}},
		},
		{
			name:   "contained range removed",
			input:  []Range{{1, 20}, {5, 10}},
			output: []Range{{1, 20}},
		},
		{
			name:   "empty input",
			input:  []Range{},
			output: []Range{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.output, mergeRanges(tc.input))
		})
	}
}

// --- intersects ---

func TestIntersects(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":10,"end":24},{"start":80,"end":80}],"src/b.py":"all"}}`))
	require.NoError(t, err)

	tests := []struct {
		name  string
		file  string
		start int
		end   int
		want  bool
	}{
		{"exact range match", "src/a.py", 10, 24, true},
		{"finding spans changed range", "src/a.py", 8, 12, true},
		{"finding inside range", "src/a.py", 15, 20, true},
		{"boundary: finding ends at start of range", "src/a.py", 5, 10, true},
		{"boundary: finding starts at end of range", "src/a.py", 24, 30, true},
		{"no intersection before range", "src/a.py", 1, 9, false},
		{"no intersection after range", "src/a.py", 25, 30, false},
		{"second range single line match", "src/a.py", 80, 80, true},
		{"second range: finding spans it", "src/a.py", 79, 81, true},
		{"between ranges", "src/a.py", 25, 79, false},
		{"all-scope file always matches", "src/b.py", 1, 9999, true},
		{"file not in scope", "src/c.py", 10, 20, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scope.Intersects(tc.file, tc.start, tc.end))
		})
	}
}

// --- GetDeltaFilter ---

func makeLocalFinding(filepath string, startLine, endLine int) local_models.FindingResource {
	sl := &local_models.IoSnykReactiveFindingSourceLocation{
		Filepath:            filepath,
		OriginalStartLine:   startLine,
		OriginalEndLine:     endLine,
	}
	loc := local_models.IoSnykReactiveFindingLocation{
		SourceLocations: sl,
	}
	locs := []local_models.IoSnykReactiveFindingLocation{loc}
	return local_models.FindingResource{
		Attributes: local_models.TypesFindingAttributes{
			Locations: &locs,
		},
	}
}

func TestGetDeltaFilter_IntersectionNotContainment(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":10,"end":10}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)

	// finding spans changed line (8-12 intersects 10-10)
	assert.True(t, f(makeLocalFinding("src/a.py", 8, 12)))
	// finding exactly on changed line
	assert.True(t, f(makeLocalFinding("src/a.py", 10, 10)))
	// finding before changed line
	assert.False(t, f(makeLocalFinding("src/a.py", 1, 9)))
	// finding after changed line
	assert.False(t, f(makeLocalFinding("src/a.py", 11, 20)))
}

func TestGetDeltaFilter_AllSentinel(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/new.py":"all"}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)
	assert.True(t, f(makeLocalFinding("src/new.py", 1, 9999)))
}

func TestGetDeltaFilter_FileNotInScope(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":10,"end":20}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)
	assert.False(t, f(makeLocalFinding("other.py", 10, 20)))
}

func TestGetDeltaFilter_PathNormalization(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":10,"end":20}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)
	// finding uses ./src/a.py — should normalize and match
	assert.True(t, f(makeLocalFinding("./src/a.py", 10, 20)))
}

func TestGetDeltaFilter_NoLocationData(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":10,"end":20}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)

	// finding with file in scope but zero line numbers — keep
	assert.True(t, f(makeLocalFinding("src/a.py", 0, 0)))
}

func TestGetDeltaFilter_NilLocations(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":10,"end":20}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)

	finding := local_models.FindingResource{
		Attributes: local_models.TypesFindingAttributes{
			Locations: nil,
		},
	}
	assert.False(t, f(finding))
}

func TestGetDeltaFilter_MultiLocationFinding(t *testing.T) {
	// finding has two locations; only the second intersects
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/b.py":[{"start":50,"end":60}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)

	sl1 := &local_models.IoSnykReactiveFindingSourceLocation{Filepath: "src/a.py", OriginalStartLine: 10, OriginalEndLine: 20}
	sl2 := &local_models.IoSnykReactiveFindingSourceLocation{Filepath: "src/b.py", OriginalStartLine: 55, OriginalEndLine: 55}
	locs := []local_models.IoSnykReactiveFindingLocation{
		{SourceLocations: sl1},
		{SourceLocations: sl2},
	}
	finding := local_models.FindingResource{
		Attributes: local_models.TypesFindingAttributes{Locations: &locs},
	}
	assert.True(t, f(finding))
}

func TestGetDeltaFilter_MultiRangeFile(t *testing.T) {
	scope, err := ParseChangedScope([]byte(`{"version":1,"files":{"src/a.py":[{"start":1,"end":5},{"start":50,"end":60}]}}`))
	require.NoError(t, err)
	f := GetDeltaFilter(scope)

	assert.True(t, f(makeLocalFinding("src/a.py", 3, 3)))
	assert.True(t, f(makeLocalFinding("src/a.py", 55, 55)))
	assert.False(t, f(makeLocalFinding("src/a.py", 10, 40)))
}
