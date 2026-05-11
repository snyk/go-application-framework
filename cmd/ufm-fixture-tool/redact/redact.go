// Package redact normalises a raw UFM test-result JSON dump into a
// deterministic fixture by replacing UUIDs, emails, and sensitive
// metadata (including stable org-scoped URLs) with placeholders.
package redact

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/pkg/utils"
)

var uuidRE = regexp.MustCompile(
	`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
)

const (
	stableOrgSlug = "my-org"
	stableEmail   = "user@example.com"

	defaultReportBase = "https://app.snyk.io/org/" + stableOrgSlug + "/project"

	// Stable metadata placeholders (keys are kept; real IDs/URLs are not echoed).
	stableMetadataProjectID  = "00000000-0000-0000-0000-000000000000"
	stableMetadataSnapshotID = "00000000-0000-0000-0000-000000000001"
)

// UUIDRemapper assigns deterministic UUIDs to every unique UUID encountered,
// in first-seen order.
type UUIDRemapper struct {
	mapping map[string]string
	counter int
}

func NewUUIDRemapper() *UUIDRemapper {
	return &UUIDRemapper{mapping: make(map[string]string)}
}

// Remap returns the stable replacement for the given UUID. If not yet seen,
// a new deterministic UUID is generated.
func (r *UUIDRemapper) Remap(value string) string {
	key := strings.ToLower(value)
	if mapped, ok := r.mapping[key]; ok {
		return mapped
	}
	r.counter++
	mapped := fmt.Sprintf("11112222-3333-4444-5555-%012x", r.counter)
	r.mapping[key] = mapped
	return mapped
}

// mapKeyIsUUID reports whether s is exactly one RFC-4122-style UUID (JSON object
// keys cannot contain multiple matches; this is used for maps like _problemRefs).
func mapKeyIsUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	return uuidRE.FindString(s) == s
}

// Fixture normalises a raw UFM JSON array ([]testresult) and returns the
// redacted bytes as indented JSON.
func Fixture(raw []byte) ([]byte, error) {
	var data []interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("expected top-level JSON array: %w", err)
	}

	ctx := walkContext{
		remapper: NewUUIDRemapper(),
	}
	redacted := walk(data, &ctx)

	out, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal redacted data: %w", err)
	}
	out = append(out, '\n')
	return out, nil
}

type walkContext struct {
	remapper *UUIDRemapper
	// inMetadata is true while walking the object under the top-level "metadata" key.
	inMetadata bool
}

func walk(node interface{}, ctx *walkContext) interface{} {
	switch v := node.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for _, k := range utils.SortedMapKeys(v) {
			val := v[k]
			outKey := k
			if mapKeyIsUUID(k) {
				outKey = ctx.remapper.Remap(k)
			}
			if k == "email" {
				out[outKey] = stableEmail
				continue
			}
			if ctx.inMetadata {
				switch k {
				case "project-id":
					out[outKey] = stableMetadataProjectID
				case "snapshot-id":
					out[outKey] = stableMetadataSnapshotID
				case "project-page-link", "report-url":
					out[outKey] = fmt.Sprintf("%s/%s", defaultReportBase, stableMetadataProjectID)
				default:
					out[outKey] = walk(val, ctx)
				}
				continue
			}

			if k == "metadata" {
				if meta, ok := val.(map[string]interface{}); ok {
					sub := *ctx
					sub.inMetadata = true
					out[outKey] = walk(meta, &sub)
					continue
				}
			}
			out[outKey] = walk(val, ctx)
		}
		return out

	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = walk(item, ctx)
		}
		return out

	case string:
		s := uuidRE.ReplaceAllStringFunc(v, ctx.remapper.Remap)
		return s

	default:
		return node
	}
}
