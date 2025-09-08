package ui

import (
	"context"
	"os"
)

//go:generate go tool github.com/golang/mock/mockgen -source=userinterface.go -destination ../mocks/userinterface.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/ui/

type UserInterface interface {
	Output(output string) error
	OutputError(err error, opts ...Opts) error
	NewProgressBar() ProgressBar
	Input(prompt string) (string, error)
}

func DefaultUi() UserInterface {
	return newConsoleUi(os.Stdin, os.Stdout, os.Stderr)
}

type uiConfig struct {
	//nolint:containedctx // internal struct used to maintain backwards compatibility
	context context.Context
}

type Opts = func(ui *uiConfig)

func WithContext(ctx context.Context) Opts {
	return func(ui *uiConfig) {
		ui.context = ctx
	}
}
