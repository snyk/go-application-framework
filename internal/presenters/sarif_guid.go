package presenters

import (
	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// ignoreRuleIDProvider is implemented by ignore details that know the policy rule
// behind the ignore. It is optional so that the exported IssueIgnoreDetails
// interface, and the implementations of it outside this module, stay unchanged.
type ignoreRuleIDProvider interface {
	GetRuleID() *string
}

// getIgnoreRuleID returns the ID of the policy rule behind an ignore, or nil if
// the ignore has none (for example legacy project ignores).
func getIgnoreRuleID(details testapi.IssueIgnoreDetails) *string {
	provider, ok := details.(ignoreRuleIDProvider)
	if !ok {
		return nil
	}
	return provider.GetRuleID()
}

// suppressionGuid is the only way a template may produce a SARIF suppression
// "guid". It takes the persistent identifier of the ignore (string or *string)
// and returns a UUIDv5 derived from it, or "" if there is none, in which case the
// template must omit the property. It never returns its input; see
// ufm_helpers.StableSARIFGUID.
func suppressionGuid(persistentID any) string {
	switch id := persistentID.(type) {
	case string:
		return ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, id)
	case *string:
		if id == nil {
			return ""
		}
		return ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, *id)
	default:
		return ""
	}
}
