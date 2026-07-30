package llm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/llm"
)

func ctx() context.Context { return context.Background() }

func TestFakeProvider_ErrorPath(t *testing.T) {
	boom := errors.New("provider exploded")
	fp := &llm.FakeProvider{Err: boom}

	_, err := fp.ChatCompletion(ctx(), &llm.ChatRequest{})
	assert.ErrorIs(t, err, boom)
}

func TestFakeProvider_Name(t *testing.T) {
	fp := &llm.FakeProvider{ProviderName: "fake"}
	assert.Equal(t, "fake", fp.Name())
}
