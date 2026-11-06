package catalog

import (
	"slices"
	"strings"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

// FindByLifecycle returns a sorted snapshot of the IDs of workflows labeled lifecycle=<lifecycle>. Entries without metadata support are skipped, as are workflows removed between listing and lookup.
func FindByLifecycle(engine workflow.Engine, lifecycle Lifecycle) []workflow.Identifier {
	return findByLabel(engine, lifecycleLabel, string(lifecycle))
}

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
