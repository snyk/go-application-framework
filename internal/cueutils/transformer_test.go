package cueutils

import (
	"fmt"
	"io"
	"os"
	"testing"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
	"github.com/snyk/go-application-framework/internal/restapimodels"
	"github.com/stretchr/testify/assert"
)

func TestNewTransformer_ValidTransformToTestApiFromCliTestManaged_Malformed(t *testing.T) {
	ctx := cuecontext.New()

	transformer, err := NewTransformer(ctx, ToTestApiFromCliTestManaged)

	assert.NoError(t, err)
	assert.NotNil(t, transformer, "Expected a non-nil transformer")

	input := loadJsonFile(t, "cli-json-test-npm.malformed.json")
	n, err := transformer.Apply(input)
	assert.Error(t, err)
	fmt.Print(n)
}

func TestNewTransformer_ValidTransformToTestApiFromSarif(t *testing.T) {
	ctx := cuecontext.New()
	transformer, err := NewTransformer(ctx, ToTestApiFromSarif)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	assert.NotNil(t, transformer, "Expected a non-nil transformer")

	input := loadJsonFile(t, "sarif-juice-shop.json")
	transformed, err := transformer.Apply(input)
	assert.NoError(t, err)

	assert.IsType(t, &restapimodels.LocalFinding{}, transformed)
	assert.Equal(t, "662d6134-2c32-55f7-9717-d60add450b1b", transformed.Findings[0].Id.String())
	assert.Len(t, transformed.Findings, 278)
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
