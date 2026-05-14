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

	for i := 1; i < 20; i++ {
		out, err := Fixture([]byte(input))
		require.NoError(t, err, "iteration %d", i)
		assert.Equal(t, string(first), string(out), "iteration %d produced different output (non-deterministic)", i)
	}

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(first, &result))

	uuids, ok := result[0]["uuids"].([]interface{})
	require.True(t, ok, `expected []interface{} at result[0]["uuids"]`)

	for i, v := range uuids {
		want := fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
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

func TestFixture_emails_replaced_anywhere(t *testing.T) {
	input := `[{"email":"alice@example.com","author":"bob@example.com","name":"set by carol@snyk.io"}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, stableEmail, result[0]["email"])
	assert.Equal(t, stableEmail, result[0]["author"])
	assert.Equal(t, "set by "+stableEmail, result[0]["name"])
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

// Markdown descriptions for OSS findings often contain "package@1.2.3"
// strings (sometimes with exotic version suffixes like Maven's `.RELEASE`,
// pre-release tags, or build metadata). The email pattern match must skip
// all of these — its domain anchor requires a leading letter, ruling out
// digit-led version suffixes.
func TestFixture_package_at_version_not_redacted(t *testing.T) {
	cases := []string{
		// Semver-ish: numeric TLD, never email-shaped.
		"got@11.8.5",
		"lodash@4.17.21",
		"requests@2.31.0",
		// Maven-style suffixes — all-alpha "TLD" looks like an email TLD.
		"org.springframework.boot@2.7.0.RELEASE",
		"com.fasterxml.jackson.core@2.13.0.Final",
		"javax.inject@1.0.0.GA",
		"org.hibernate@5.4.0.SR1",
		// Pre-release / build-metadata tags.
		"react@18.2.0-alpha",
		"vue@3.0.0-rc.1",
		"webpack@5.0.0-beta.1",
		"libfoo@1.0.0-SNAPSHOT",
		"gem@1.0.0+build.123",
		// Architecture/platform suffixes.
		"nokogiri@1.13.4-x86_64-linux",
		// Operators / globs commonly seen in advisories.
		"lodash@^4.17.21",
		"package@~1.2.3",
		"foo@1.x",
		"@scope/package@1.0.0",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			input := fmt.Sprintf(`[{"description":"Upgrade %s for the fix."}]`, c)
			out, err := Fixture([]byte(input))
			require.NoError(t, err)

			var result []map[string]interface{}
			require.NoError(t, json.Unmarshal(out, &result))

			desc, ok := result[0]["description"].(string)
			assert.True(t, ok)
			assert.Contains(t, desc, c, "package@version must be left untouched, got %q", desc)
			assert.NotContains(t, desc, stableEmail)
		})
	}
}

func TestFixture_UUIDs_in_strings_remapped(t *testing.T) {
	input := `[{"url":"https://snyk.io/projects/aaaaaaaa-1111-2222-3333-444444444444/report"}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	url, ok := result[0]["url"].(string)
	assert.True(t, ok)
	assert.NotContains(t, url, "aaaaaaaa-1111-2222-3333-444444444444", "original UUID still present")
	matches := uuidRE.FindAllString(url, -1)
	require.Len(t, matches, 1)
	assert.True(t, strings.HasPrefix(matches[0], "00000000-0000-0000-0000-"), "expected placeholder UUID, got %q", matches[0])
}

func TestFixture_snyk_org_slug_swapped(t *testing.T) {
	// Covers every Snyk app subdomain (production, regional, internal envs)
	// so the redacted fixture doesn't leak the originating org slug.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"app", "https://app.snyk.io/org/real-org-slug/project", "https://app.snyk.io/org/my-org/project"},
		{"dev", "https://app.dev.snyk.io/org/another-slug/project/x", "https://app.snyk.io/org/my-org/project/x"},
		{"eu", "https://app.eu.snyk.io/org/eu-team/dashboard", "https://app.snyk.io/org/my-org/dashboard"},
		{"path_only", "https://app.snyk.io/org/slug-with-dashes-123", "https://app.snyk.io/org/my-org"},
		{"project_with_uuid", "https://app.dev.snyk.io/org/real-org/project/aaaaaaaa-1111-2222-3333-444444444444/report", "https://app.snyk.io/org/my-org/project/00000000-0000-0000-0000-000000000001/report"},
		{"non_snyk_left_alone", "https://github.com/org/some-org/repo", "https://github.com/org/some-org/repo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := fmt.Sprintf(`[{"link":%q}]`, tc.in)
			out, err := Fixture([]byte(input))
			require.NoError(t, err)

			var result []map[string]interface{}
			require.NoError(t, json.Unmarshal(out, &result))

			link, ok := result[0]["link"].(string)
			assert.True(t, ok)
			assert.Equal(t, tc.want, link)
		})
	}
}

func TestFixture_metadata_project_id_remapped_as_uuid(t *testing.T) {
	// project-id used to have a hard-coded placeholder. Now it's just a
	// UUID-valued string and should be handled by the generic UUID remapper.
	input := `[{"metadata":{"project-id":"aaaaaaaa-1111-2222-3333-444444444444","snapshot-id":"bbbbbbbb-1111-2222-3333-444444444444","report-url":"https://app.snyk.io/org/real-org/project/aaaaaaaa-1111-2222-3333-444444444444","kept":"value"}}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	meta, ok := result[0]["metadata"].(map[string]interface{})
	assert.True(t, ok)

	projectID, ok := meta["project-id"].(string)
	assert.True(t, ok)
	assert.True(t, strings.HasPrefix(projectID, "00000000-0000-0000-0000-"), "project-id should be remapped, got %q", projectID)

	snapshotID, ok := meta["snapshot-id"].(string)
	assert.True(t, ok)
	assert.True(t, strings.HasPrefix(snapshotID, "00000000-0000-0000-0000-"), "snapshot-id should be remapped, got %q", snapshotID)
	assert.NotEqual(t, projectID, snapshotID)

	reportURL, ok := meta["report-url"].(string)
	assert.True(t, ok)
	wantURL := "https://app.snyk.io/org/" + stableOrgSlug + "/project/" + projectID
	assert.Equal(t, wantURL, reportURL, "URL keeps domain, swaps org slug, reuses remapped project-id")
	assert.Equal(t, "value", meta["kept"])
}

func TestFixture_nested_arrays(t *testing.T) {
	input := `[{"items":[{"id":"aaaaaaaa-1111-2222-3333-444444444444"},{"id":"bbbbbbbb-1111-2222-3333-444444444444"}]}]`
	out, err := Fixture([]byte(input))
	require.NoError(t, err)

	var result []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	items, ok := result[0]["items"].([]interface{})
	assert.True(t, ok)
	require.Len(t, items, 2)

	item0, ok := items[0].(map[string]interface{})
	assert.True(t, ok)
	item1, ok := items[1].(map[string]interface{})
	assert.True(t, ok)

	id1, ok := item0["id"].(string)
	assert.True(t, ok)
	id2, ok := item1["id"].(string)
	assert.True(t, ok)

	assert.True(t, strings.HasPrefix(id1, "00000000-0000-0000-0000-"), "nested UUID should use placeholder prefix, got %q", id1)
	assert.True(t, strings.HasPrefix(id2, "00000000-0000-0000-0000-"), "nested UUID should use placeholder prefix, got %q", id2)
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
	assert.True(t, ok)
	problems, ok := root["problems"].([]interface{})
	assert.True(t, ok)
	require.Len(t, problems, 2)

	p0, ok := problems[0].(map[string]interface{})
	assert.True(t, ok)
	p1, ok := problems[1].(map[string]interface{})
	assert.True(t, ok)
	id0, ok := p0["id"].(string)
	assert.True(t, ok)
	id1, ok := p1["id"].(string)
	assert.True(t, ok)
	require.NotEmpty(t, id0)
	require.NotEmpty(t, id1)

	assert.Contains(t, refs, id0, "_problemRefs should contain key matching first problem id")
	assert.Contains(t, refs, id1, "_problemRefs should contain key matching second problem id")
}

func TestFixture_input_validation(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantOutput  string
		wantErrText string
	}{
		{"invalid_json", "not json", "", "expected top-level JSON array"},
		{"object_not_array", `{"key":"value"}`, "", "expected top-level JSON array"},
		{"empty_array", `[]`, "[]\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Fixture([]byte(tc.input))
			if tc.wantErrText != "" {
				assert.ErrorContains(t, err, tc.wantErrText)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantOutput, string(out))
		})
	}
}

func TestUUIDRemapper_incremental(t *testing.T) {
	r := NewUUIDRemapper()
	a := r.Remap("aaaaaaaa-1111-2222-3333-444444444444")
	b := r.Remap("bbbbbbbb-1111-2222-3333-444444444444")

	assert.NotEqual(t, a, b, "different inputs should produce different outputs")
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", a)
	assert.Equal(t, "00000000-0000-0000-0000-000000000002", b)

	a2 := r.Remap("AAAAAAAA-1111-2222-3333-444444444444")
	assert.Equal(t, a, a2, "case-insensitive lookup should return the same mapped UUID")
}
