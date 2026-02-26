package ui

import (
	"context"

	"github.com/snyk/go-application-framework/pkg/ui/consoleui"
	"github.com/snyk/go-application-framework/pkg/ui/uitypes"
)

// Type aliases for backward compatibility - these point to uitypes package
type (
	UserInterface    = uitypes.UserInterface
	ProgressBar      = uitypes.ProgressBar
	Opts             = uitypes.Opts
	EmptyProgressBar = uitypes.EmptyProgressBar
)

// Constant aliases for backward compatibility
const InfiniteProgress = uitypes.InfiniteProgress

// WithContext returns an Opts that sets the context.
// This is an alias for uitypes.WithContext for backward compatibility.
func WithContext(ctx context.Context) Opts {
	return uitypes.WithContext(ctx)
}

// DefaultUi returns a default console-based UserInterface.
func DefaultUi() UserInterface {
	return consoleui.New()
}
