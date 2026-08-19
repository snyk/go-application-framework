package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

// Range is an inclusive, 1-based line range.
type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// fileScope is the per-file scope value: either all lines or a list of merged ranges.
type fileScope struct {
	all    bool
	ranges []Range
}

func (f *fileScope) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "all" {
			f.all = true
			return nil
		}
		return fmt.Errorf("invalid file scope string %q; expected \"all\"", s)
	}

	var ranges []Range
	if err := json.Unmarshal(data, &ranges); err != nil {
		return fmt.Errorf("file scope must be \"all\" or [{\"start\":N,\"end\":M},...]")
	}
	for _, r := range ranges {
		if r.Start <= 0 || r.End <= 0 {
			return fmt.Errorf("line numbers must be positive (got start=%d end=%d)", r.Start, r.End)
		}
		if r.Start > r.End {
			return fmt.Errorf("start %d > end %d in range", r.Start, r.End)
		}
	}
	f.ranges = mergeRanges(ranges)
	return nil
}

type changedScopeJSON struct {
	Version *int                       `json:"version"`
	Files   map[string]json.RawMessage `json:"files"`
}

// ChangedScope holds validated delta input.
type ChangedScope struct {
	files map[string]fileScope
}

// ParseChangedScope validates and parses the changed-lines JSON input.
// Returns an error for malformed input; callers should fail closed.
func ParseChangedScope(data []byte) (ChangedScope, error) {
	var raw changedScopeJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return ChangedScope{}, fmt.Errorf("changed-lines input is not valid JSON: %w", err)
	}
	if raw.Version == nil {
		return ChangedScope{}, fmt.Errorf("changed-lines input missing required \"version\" field")
	}
	if *raw.Version != 1 {
		return ChangedScope{}, fmt.Errorf("changed-lines version must be 1 (got %d)", *raw.Version)
	}
	if raw.Files == nil {
		return ChangedScope{}, fmt.Errorf("changed-lines input missing required \"files\" object")
	}
	if len(raw.Files) == 0 {
		return ChangedScope{}, fmt.Errorf("changed-lines input contained no files; omit the flag for a full scan")
	}

	scope := ChangedScope{files: make(map[string]fileScope, len(raw.Files))}
	for path, rawScope := range raw.Files {
		var fs fileScope
		if err := json.Unmarshal(rawScope, &fs); err != nil {
			return ChangedScope{}, fmt.Errorf("invalid scope for file %q: %w", path, err)
		}
		scope.files[NormalizeRelPath(path)] = fs
	}
	return scope, nil
}

// NormalizeRelPath converts a file path to relative, forward-slash, no-leading-./ form.
// Backslashes are always converted to forward-slashes regardless of OS.
func NormalizeRelPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimLeft(p, "/")
	return p
}

// mergeRanges merges overlapping/adjacent inclusive ranges and returns them sorted.
func mergeRanges(ranges []Range) []Range {
	if len(ranges) == 0 {
		return ranges
	}
	sorted := make([]Range, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End < sorted[j].End
	})
	merged := []Range{sorted[0]}
	for _, r := range sorted[1:] {
		last := &merged[len(merged)-1]
		if r.Start <= last.End+1 { // adjacent or overlapping
			if r.End > last.End {
				last.End = r.End
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}

// FileInScope returns true if the normalised file path exists in the scope.
func (s ChangedScope) FileInScope(file string) bool {
	_, ok := s.files[file]
	return ok
}

// Intersects returns true if [findStart, findEnd] intersects any range for the given normalised file.
func (s ChangedScope) Intersects(file string, findStart, findEnd int) bool {
	fs, ok := s.files[file]
	if !ok {
		return false
	}
	if fs.all {
		return true
	}
	for _, r := range fs.ranges {
		if findStart <= r.End && findEnd >= r.Start {
			return true
		}
	}
	return false
}

// GetDeltaFilter returns a FindingsFilterFunc for LOCAL_FINDING_MODEL findings.
// A finding is kept if any of its source locations intersects the changed scope.
// A finding whose file is in scope but has no line data is kept (false positive
// beats false negative for a security gate).
func GetDeltaFilter(scope ChangedScope) FindingsFilterFunc {
	return func(finding local_models.FindingResource) bool {
		if finding.Attributes.Locations == nil || len(*finding.Attributes.Locations) == 0 {
			return false
		}
		for _, loc := range *finding.Attributes.Locations {
			if loc.SourceLocations == nil {
				continue
			}
			sl := loc.SourceLocations
			normPath := NormalizeRelPath(sl.Filepath)
			if !scope.FileInScope(normPath) {
				continue
			}
			// file in scope, no line data — keep
			if sl.OriginalStartLine == 0 && sl.OriginalEndLine == 0 {
				return true
			}
			end := sl.OriginalEndLine
			if end == 0 {
				end = sl.OriginalStartLine
			}
			if scope.Intersects(normPath, sl.OriginalStartLine, end) {
				return true
			}
		}
		return false
	}
}
