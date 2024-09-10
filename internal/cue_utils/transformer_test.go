package cue_utils

import (
	"io"
	"os"
	"testing"

	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
)

func TestNewTransformer_ValidTransformToTestApiFromCliTestManaged(t *testing.T) {
	ctx := cuecontext.New()

	//
	jsonFile, err := os.Open("./testdata/inputs/cli-json-test-npm.json")
	if err != nil {
		t.Errorf("Failed to load json")
	}
	defer func(jsonFile *os.File) {
		jsonErr := jsonFile.Close()
		if jsonErr != nil {
			t.Errorf("Failed to close json")
		}
	}(jsonFile)
	byteValue, _ := io.ReadAll(jsonFile)
	input, errUnJson := cuejson.Unmarshal(byteValue)

	if errUnJson != nil {
		t.Errorf("Unexpected error parsing JSON: %v", err)
	}

	transformer, err := NewTransformer(ctx, ToTestApiFromCliTestManaged)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if transformer == nil {
		t.Error("Expected a non-nil transformer")
	}

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
