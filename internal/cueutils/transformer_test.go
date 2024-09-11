package cueutils

import (
	"io"
	"os"
	"testing"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
	"github.com/stretchr/testify/assert"
)

func TestNewTransformer_ValidTransformToTestApiFromCliTestManaged(t *testing.T) {
	ctx := cuecontext.New()

	transformer, err := NewTransformer(ctx, ToTestApiFromCliTestManaged)

	assert.NoError(t, err)
	assert.NotNil(t, transformer, "Expected a non-nil transformer")

	input := loadJsonFile(t, "cli-json-test-npm.json")
	_, applyError := transformer.Apply(input)
	assert.NoError(t, applyError)
}

func TestNewTransformer_ValidTransformToTestApiFromSarif(t *testing.T) {
	ctx := cuecontext.New()
	transformer, err := NewTransformer(ctx, ToTestApiFromSarif)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	assert.NotNil(t, transformer, "Expected a non-nil transformer")

	input := loadJsonFile(t, "sarif-juice-shop.json")
	_, applyError := transformer.Apply(input)
	assert.NoError(t, applyError)
}

func TestNewTransformer_ValidTransformToCliFromTestApi(t *testing.T) {
	ctx := cuecontext.New()
	transformer, err := NewTransformer(ctx, ToCliFromTestApi)

	assert.NoError(t, err)

	assert.NotNil(t, transformer, "Expected a non-nil transformer")
}

func TestNewTransformer_InvalidTransform(t *testing.T) {
	ctx := cuecontext.New()
	_, err := NewTransformer(ctx, "invalid_transform.cue")
	assert.Error(t, err)
}

func loadJsonFile(t *testing.T, filename string) ast.Expr {
	t.Helper()

	jsonFile, err := os.Open("./testdata/inputs/" + filename)
	if err != nil {
		t.Errorf("Failed to load json")
	}
	defer func(jsonFile *os.File) {
		jsonErr := jsonFile.Close()
		assert.NoError(t, jsonErr)
	}(jsonFile)
	byteValue, jsonReadAllErr := io.ReadAll(jsonFile)
	assert.NoError(t, jsonReadAllErr)

	input, errUnJson := cuejson.Unmarshal(byteValue)

	assert.NoError(t, errUnJson)
	return input
}
