package cueutils

import (
	"io"
	"os"
	"testing"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
)

func TestNewTransformer_ValidTransformToTestApiFromCliTestManaged(t *testing.T) {
	ctx := cuecontext.New()

	transformer, err := NewTransformer(ctx, ToTestApiFromCliTestManaged)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if transformer == nil {
		t.Error("Expected a non-nil transformer")
	}

	input := loadJsonFile(t, "cli-json-test-npm.json")
	_, applyError := transformer.Apply(input)
	if applyError == nil {
		t.Fatal(err)
	}
}

func TestNewTransformer_ValidTransformToTestApiFromSarif(t *testing.T) {
	ctx := cuecontext.New()
	transformer, err := NewTransformer(ctx, ToTestApiFromSarif)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if transformer == nil {
		t.Error("Expected a non-nil transformer")
	}

	input := loadJsonFile(t, "sarif-juice-shop.json")
	_, applyError := transformer.Apply(input)
	if applyError == nil {
		t.Fatal(err)
	}
}

func TestNewTransformer_ValidTransformToCliFromTestApi(t *testing.T) {
	ctx := cuecontext.New()
	transformer, err := NewTransformer(ctx, ToCliFromTestApi)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if transformer == nil {
		t.Error("Expected a non-nil transformer")
	}
}

func TestNewTransformer_InvalidTransform(t *testing.T) {
	ctx := cuecontext.New()
	_, err := NewTransformer(ctx, "invalid_transform.cue")
	if err == nil {
		t.Error("Expected an error for invalid transform")
	}
}

func loadJsonFile(t *testing.T, filename string) ast.Expr {
	t.Helper()

	jsonFile, err := os.Open("./testdata/inputs/" + filename)
	if err != nil {
		t.Errorf("Failed to load json")
	}
	defer func(jsonFile *os.File) {
		jsonErr := jsonFile.Close()
		if jsonErr != nil {
			t.Errorf("Failed to close json")
		}
	}(jsonFile)
	byteValue, jsonReadAllErr := io.ReadAll(jsonFile)
	if jsonReadAllErr != nil {
		t.Errorf("Unexpected error reading JSON file %v", jsonReadAllErr)
	}

	input, errUnJson := cuejson.Unmarshal(byteValue)

	if errUnJson != nil {
		t.Errorf("Unexpected error parsing JSON: %v", err)
	}
	return input
}
