package redact

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixture_UUIDs_are_deterministic(t *testing.T) {
	// Pure array of UUIDs — no maps involved — so traversal order is
	// fully governed by array indices, not Go's random map iteration.
	input := `[{"uuids":[
		"aaaaaaaa-0001-0001-0001-aaaaaaaaaaaa",
		"aaaaaaaa-0002-0002-0002-aaaaaaaaaaaa",
		"aaaaaaaa-0003-0003-0003-aaaaaaaaaaaa",
		"aaaaaaaa-0004-0004-0004-aaaaaaaaaaaa",
		"aaaaaaaa-0005-0005-0005-aaaaaaaaaaaa",
		"aaaaaaaa-0006-0006-0006-aaaaaaaaaaaa",
		"aaaaaaaa-0007-0007-0007-aaaaaaaaaaaa",
		"aaaaaaaa-0008-0008-0008-aaaaaaaaaaaa",
		"aaaaaaaa-0009-0009-0009-aaaaaaaaaaaa",
		"aaaaaaaa-0010-0010-0010-aaaaaaaaaaaa"
	]}]`

	first, err := Fixture([]byte(input))
	require.NoError(t, err)

	// Run 20 times — every run must produce byte-identical output.
	for i := 1; i < 20; i++ {
		out, err := Fixture([]byte(input))
		require.NoError(t, err, "iteration %d", i)
		assert.Equal(t, string(first), string(out), "iteration %d produced different output (non-deterministic)", i)
	}

	// Verify the exact sequential counter: array position 0 gets counter
	// 1, position 1 gets counter 2, etc.
	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(first, &result))

	uuids, ok := result[0]["uuids"].([]interface{})
	require.True(t, ok, `expected []interface{} at result[0]["uuids"]`)

	for i, v := range uuids {
		want := fmt.Sprintf("11112222-3333-4444-5555-%012x", i+1)
		got, ok := v.(string)
		require.True(t, ok, "uuids[%d]: expected string, got %T", i, v)
		assert.Equal(t, want, got, "uuids[%d]", i)
	}
}

func TestFixture_same_UUID_maps_to_same_replacement(t *testing.T) {
	input := `[{"a":"aaaaaaaa-1111-2222-3333-444444444444","b":"aaaaaaaa-1111-2222-3333-444444444444"}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, result[0]["a"], result[0]["b"], "same source UUID should map to the same replacement")
}

func TestFixture_email_field_replaced(t *testing.T) {
	input := `[{"email":"alice@example.com","author":"bob@example.com"}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, stableEmail, result[0]["email"])
	assert.Equal(t, "bob@example.com", result[0]["author"], "author is not the 'email' key, should pass through")
}

func TestFixture_email_field_in_nested_object(t *testing.T) {
	input := `[{"user":{"email":"deep@nested.com","name":"Alice"}}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	user, ok := result[0]["user"].(map[string]interface{})
	require.True(t, ok, `expected map at result[0]["user"]`)

	assert.Equal(t, stableEmail, user["email"])
	assert.Equal(t, "Alice", user["name"], "non-email fields should pass through")
}

func TestFixture_UUIDs_in_URLs_remapped(t *testing.T) {
	input := `[{"url":"https://app.snyk.io/org/foo/project/aaaaaaaa-1111-2222-3333-444444444444/report"}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	url, ok := result[0]["url"].(string)
	require.True(t, ok, `expected string at result[0]["url"]`)

	assert.NotEqual(t, input, url, "URL should have been transformed")
	assert.False(t, strings.Contains(url, "aaaaaaaa-1111-2222-3333-444444444444"), "original UUID still present in URL")
}

func TestFixture_metadata_redacted(t *testing.T) {
	input := `[{"metadata":{"project-id":"aaaaaaaa-1111-2222-3333-444444444444","snapshot-id":"bbbbbbbb-1111-2222-3333-444444444444","project-page-link":"https://example.com","report-url":"https://old","kept":"value"}}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	meta, ok := result[0]["metadata"].(map[string]interface{})
	require.True(t, ok, `expected map at result[0]["metadata"]`)

	wantPage := fmt.Sprintf("https://app.snyk.io/org/my-org/project/%s", stableMetadataProjectID)

	assert.Equal(t, stableMetadataProjectID, meta["project-id"])
	assert.Equal(t, stableMetadataSnapshotID, meta["snapshot-id"])
	assert.Equal(t, wantPage, meta["project-page-link"])
	assert.Equal(t, wantPage, meta["report-url"])
	assert.Equal(t, "value", meta["kept"])
}

func TestFixture_metadata_without_report_url(t *testing.T) {
	input := `[{"metadata":{"kept":"value"}}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	meta, ok := result[0]["metadata"].(map[string]interface{})
	require.True(t, ok, `expected map at result[0]["metadata"]`)

	assert.NotContains(t, meta, "report-url", "report-url should not be injected when absent from input")
	assert.Equal(t, "value", meta["kept"])
}

func TestFixture_nested_arrays(t *testing.T) {
	input := `[{"items":[{"id":"aaaaaaaa-1111-2222-3333-444444444444"},{"id":"bbbbbbbb-1111-2222-3333-444444444444"}]}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	items, ok := result[0]["items"].([]interface{})
	require.True(t, ok, `expected []interface{} at result[0]["items"]`)
	require.Len(t, items, 2)

	item0, ok := items[0].(map[string]interface{})
	require.True(t, ok, "expected map at items[0]")
	item1, ok := items[1].(map[string]interface{})
	require.True(t, ok, "expected map at items[1]")

	id1, ok := item0["id"].(string)
	require.True(t, ok, `expected string at items[0]["id"]`)
	id2, ok := item1["id"].(string)
	require.True(t, ok, `expected string at items[1]["id"]`)

	assert.NotEqual(t, "aaaaaaaa-1111-2222-3333-444444444444", id1, "nested UUID should be remapped")
	assert.NotEqual(t, "bbbbbbbb-1111-2222-3333-444444444444", id2, "nested UUID should be remapped")
	assert.NotEqual(t, id1, id2, "different UUIDs should map to different replacements")
}

func TestFixture_problem_ref_map_keys_share_UUID_mapping_with_values(t *testing.T) {
	// _problemRefs uses problem UUIDs as JSON object keys; the same UUID appears
	// in problem "id" fields. Keys must go through the same remapper as values.
	input := `[{
		"_problemRefs": {
			"aaaaaaaa-1111-2222-3333-444444444444": ["generic-secret"],
			"bbbbbbbb-1111-2222-3333-444444444444": ["private-key"]
		},
		"problems": [
			{"id": "aaaaaaaa-1111-2222-3333-444444444444"},
			{"id": "bbbbbbbb-1111-2222-3333-444444444444"}
		]
	}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	root := result[0]
	refs, ok := root["_problemRefs"].(map[string]interface{})
	require.True(t, ok, "expected map at _problemRefs")

	problems, ok := root["problems"].([]interface{})
	require.True(t, ok, "expected []interface{} at problems")
	require.Len(t, problems, 2)

	p0, ok := problems[0].(map[string]interface{})
	require.True(t, ok, "problems[0] should be an object")
	p1, ok := problems[1].(map[string]interface{})
	require.True(t, ok, "problems[1] should be an object")
	id0, ok := p0["id"].(string)
	require.True(t, ok, "problems[0].id should be a string")
	id1, ok := p1["id"].(string)
	require.True(t, ok, "problems[1].id should be a string")
	require.NotEmpty(t, id0, "problems[0].id")
	require.NotEmpty(t, id1, "problems[1].id")

	assert.Contains(t, refs, id0, "_problemRefs should contain key matching first problem id")
	assert.Contains(t, refs, id1, "_problemRefs should contain key matching second problem id")
}

func TestFixture_invalid_json(t *testing.T) {
	_, err := Fixture([]byte(`not json`))
	assert.Error(t, err)
}

func TestFixture_non_array_json(t *testing.T) {
	_, err := Fixture([]byte(`{"key":"value"}`))
	assert.Error(t, err)
}

func TestUUIDRemapper_incremental(t *testing.T) {
	r := NewUUIDRemapper()
	a := r.Remap("aaaaaaaa-1111-2222-3333-444444444444")
	b := r.Remap("bbbbbbbb-1111-2222-3333-444444444444")

	assert.NotEqual(t, a, b, "different inputs should produce different outputs")
	assert.Equal(t, "11112222-3333-4444-5555-000000000001", a)
	assert.Equal(t, "11112222-3333-4444-5555-000000000002", b)

	a2 := r.Remap("AAAAAAAA-1111-2222-3333-444444444444")
	assert.Equal(t, a, a2, "case-insensitive lookup should return the same mapped UUID")
}
