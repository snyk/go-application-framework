package ufm_helpers

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sarifGUIDPattern is the pattern the SARIF 2.1.0 schema requires for GUIDs.
const sarifGUIDPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`

func Test_StableSARIFGUID_isVersion5(t *testing.T) {
	result := StableSARIFGUID(KindSuppression, uuid.NewString())

	parsed, err := uuid.Parse(result)
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(5), parsed.Version())
	assert.Equal(t, uuid.RFC4122, parsed.Variant())
	assert.Regexp(t, sarifGUIDPattern, result)
}

func Test_StableSARIFGUID_isDeterministic(t *testing.T) {
	id := uuid.NewString()

	assert.Equal(t, StableSARIFGUID(KindSuppression, id), StableSARIFGUID(KindSuppression, id))
}

func Test_StableSARIFGUID_distinguishesInput(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()

	assert.NotEqual(t, StableSARIFGUID(KindSuppression, a), StableSARIFGUID(KindSuppression, b))
	assert.NotEqual(t, StableSARIFGUID(KindSuppression, a), StableSARIFGUID("other", a))
}

func Test_StableSARIFGUID_partBoundariesAreUnambiguous(t *testing.T) {
	assert.NotEqual(t,
		StableSARIFGUID(KindSuppression, "a", "bc"),
		StableSARIFGUID(KindSuppression, "ab", "c"))
	assert.NotEqual(t,
		StableSARIFGUID(KindSuppression, "ab"),
		StableSARIFGUID(KindSuppression, "a", "b"))
}

func Test_StableSARIFGUID_normalisesUUIDNotation(t *testing.T) {
	id := uuid.New()
	expected := StableSARIFGUID(KindSuppression, id.String())

	assert.Equal(t, expected, StableSARIFGUID(KindSuppression, strings.ToUpper(id.String())))
	assert.Equal(t, expected, StableSARIFGUID(KindSuppression, " "+id.String()+" "))
	assert.Equal(t, expected, StableSARIFGUID(KindSuppression, "urn:uuid:"+id.String()))
	assert.Equal(t, expected, StableSARIFGUID(KindSuppression, "{"+id.String()+"}"))
}

func Test_StableSARIFGUID_omitsMissingInput(t *testing.T) {
	tests := map[string][]string{
		"no parts":        {},
		"empty part":      {""},
		"blank part":      {"   "},
		"nil UUID":        {uuid.Nil.String()},
		"nil UUID upper":  {strings.ToUpper(uuid.Nil.String())},
		"one empty of 2":  {uuid.NewString(), ""},
		"one blank of 2":  {"", uuid.NewString()},
		"nil UUID of two": {uuid.NewString(), uuid.Nil.String()},
	}

	for name, parts := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, StableSARIFGUID(KindSuppression, parts...))
		})
	}
	assert.Empty(t, StableSARIFGUID("", uuid.NewString()), "blank kind")
}

// A different UUID version of the same-looking value must never be forwarded
// and must never make the output invalid, whatever a backend service mints in future.
func Test_StableSARIFGUID_neverForwardsInput(t *testing.T) {
	for version := 1; version <= 8; version++ {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			input := uuidWithVersion(t, version)

			result := StableSARIFGUID(KindSuppression, input)

			assert.NotEqual(t, input, result)
			assert.Regexp(t, sarifGUIDPattern, result)
			parsed, err := uuid.Parse(result)
			require.NoError(t, err)
			assert.Equal(t, uuid.Version(5), parsed.Version())
		})
	}
}

func Test_StableSARIFGUID_nonUUIDInput(t *testing.T) {
	result := StableSARIFGUID(KindSuppression, "not-a-uuid")

	assert.Regexp(t, sarifGUIDPattern, result)
	assert.Equal(t, result, StableSARIFGUID(KindSuppression, "not-a-uuid"))
}

func Test_StableSARIFGUID_concurrentUse(t *testing.T) {
	id := uuid.NewString()
	expected := StableSARIFGUID(KindSuppression, id)

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			assert.Equal(t, expected, StableSARIFGUID(KindSuppression, id))
		})
	}
	wg.Wait()
}

// uuidWithVersion builds a syntactically valid UUID with the given version nibble.
func uuidWithVersion(t *testing.T, version int) string {
	t.Helper()
	id := uuid.New()
	id[6] = byte(version<<4) | (id[6] & 0x0f)
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}
