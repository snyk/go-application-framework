package catalog

import (
	"slices"
	"strings"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

// FindByLifecycle returns the IDs of the workflows of the engine that are labeled lifecycle=<lifecycle>, sorted by ID.
//
// The result is a snapshot. Entries without metadata support are skipped. A workflow that is removed or replaced between
// listing and lookup is skipped or seen as its current entry; it never causes a panic. The engine is only used through
// its workflow.Engine methods, so wrapped engines work.
func FindByLifecycle(engine workflow.Engine, lifecycle Lifecycle) []workflow.Identifier {
	return findByLabel(engine, lifecycleLabel, string(lifecycle))
}

// findByLabel returns the sorted IDs of the workflows whose label name has the given value.
func findByLabel(engine workflow.Engine, name, value string) []workflow.Identifier {
	var matches []workflow.Identifier
	for _, id := range engine.GetWorkflows() {
		entry, ok := engine.GetWorkflow(id)
		if !ok || entry == nil {
			continue
		}
		withMetadata, ok := entry.(workflow.EntryWithMetadata)
		if !ok {
			continue
		}
		if labelValue, ok := withMetadata.Metadata()[labelPrefix+name].(string); ok && labelValue == value {
			matches = append(matches, id)
		}
	}
	slices.SortFunc(matches, func(a, b workflow.Identifier) int {
		return strings.Compare(a.String(), b.String())
	})
	return matches
}
