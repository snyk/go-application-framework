// Package redact normalises a raw UFM test-result JSON dump into a
// deterministic fixture by replacing UUIDs, emails, and Snyk org slugs
// inside URLs with stable placeholders.
package redact

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/pkg/utils"
)

const (
	stableOrgSlug = "my-org"
	stableEmail   = "user@snyk.com"
	stableOrgURL  = "https://app.snyk.io/org/" + stableOrgSlug
)

var (
	uuidRE       = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	snykOrgURLRE = regexp.MustCompile(`https?://[a-z0-9.-]*\bsnyk\.io/org/[^/?#]+`)
	emailRE      = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
)

// UUIDRemapper assigns deterministic UUIDs to every unique UUID it sees,
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
	mapped := fmt.Sprintf("00000000-0000-0000-0000-%012d", r.counter)
	r.mapping[key] = mapped
	return mapped
}

// Fixture normalises a raw UFM JSON array ([]testresult) and returns the
// redacted bytes as indented JSON.
func Fixture(raw []byte) ([]byte, error) {
	var data []interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("expected top-level JSON array: %w", err)
	}

	ctx := walkContext{remapper: NewUUIDRemapper()}
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
}

func walk(node any, ctx *walkContext) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, k := range utils.SortedMapKeys(v) {
			redactedKey := redactString(k, ctx)
			out[redactedKey] = walk(v[k], ctx)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = walk(item, ctx)
		}
		return out
	case string:
		return redactString(v, ctx)
	default:
		return node
	}
}

func redactString(s string, ctx *walkContext) string {
	s = uuidRE.ReplaceAllStringFunc(s, ctx.remapper.Remap)
	s = snykOrgURLRE.ReplaceAllString(s, stableOrgURL)
	s = emailRE.ReplaceAllString(s, stableEmail)
	return s
}
