package cueutils

import (
	"fmt"
	"io"
	"os"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/gocode/gocodec"
	cuejson "cuelang.org/go/pkg/encoding/json"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
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

	assert.IsType(t, cue.Value{}, transformed)

	codec := gocodec.New(ctx, &gocodec.Config{})
	var localFinding local_models.LocalFinding

	encodeErr := codec.Encode(transformed, &localFinding)
	assert.NoError(t, encodeErr)

	assert.IsType(t, local_models.LocalFinding{}, localFinding)
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
	byteValue, err := io.ReadAll(jsonFile)
	assert.NoError(t, err)

	input, errUnJson := cuejson.Unmarshal(byteValue)

	assert.NoError(t, errUnJson)
	return input
}
