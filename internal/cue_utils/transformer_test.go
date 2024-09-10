package cue_utils

import (
	"testing"

	"cuelang.org/go/cue/cuecontext"
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
