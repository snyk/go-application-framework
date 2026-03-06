package uitypes

import "context"

//go:generate go tool github.com/golang/mock/mockgen -source=types.go -destination ../../mocks/userinterface.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/ui/uitypes/

// UserInterface defines the interface for user interaction.
type UserInterface interface {
	Output(output string) error
	OutputError(err error, opts ...Opts) error
	NewProgressBar() ProgressBar
	Input(prompt string) (string, error)
	SelectOptions(prompt string, options []string) (int, string, error)
}

// ProgressBar is an interface for interacting with some visual progress-bar.
// It is used to show the progress of some running task (or multiple).
// Example (Infinite Progress without a value):
//
//	var pBar ProgressBar = ui.DefaultUi().NewProgressBar()
//	defer pBar.Clear()
//	pBar.SetTitle("Downloading...")
//	_ = pBar.UpdateProgress(ui.InfiniteProgress)
//
// Example (with a value):
//
//	var pBar ProgressBar = ui.DefaultUi().NewProgressBar()
//	defer pBar.Clear()
//	pBar.SetTitle("Downloading...")
//	for i := 0; i <= 50; i++ {
//	    pBar.UpdateProgress(float64(i) / 100.0)
//	    time.Sleep(time.Millisecond * 50)
//	}
//
//	pBar.SetTitle("Installing...")
//	for i := 50; i <= 100; i++ {
//	    pBar.UpdateProgress(float64(i) / 100.0)
//	    time.Sleep(time.Millisecond * 50)
//	}
//
// The title can be changed in the middle of the progress bar.
type ProgressBar interface {
	// UpdateProgress updates the state of the progress bar.
	// The argument `progress` should be a float64 between 0 and 1,
	// where 0 represents 0% completion, and 1 represents 100% completion.
	// Returns an error if the update operation fails.
	UpdateProgress(progress float64) error

	// SetTitle sets the title of the progress bar, which is displayed next to the bar.
	// The title provides context or description for the operation that is being tracked.
	SetTitle(title string)

	// Clear removes the progress bar from the terminal.
	// Returns an error if the clearing operation fails.
	Clear() error
}

// EmptyProgressBar is a no-op implementation of ProgressBar.
type EmptyProgressBar struct{}

func (EmptyProgressBar) UpdateProgress(float64) error { return nil }
func (EmptyProgressBar) SetTitle(string)              {}
func (EmptyProgressBar) Clear() error                 { return nil }

// UIConfig holds configuration for UI operations.
type UIConfig struct {
	//nolint:containedctx // internal struct used to maintain backwards compatibility
	Context context.Context
}

// Opts is a functional option for configuring UI operations.
type Opts = func(cfg *UIConfig)

// WithContext returns an Opts that sets the context.
func WithContext(ctx context.Context) Opts {
	return func(cfg *UIConfig) {
		cfg.Context = ctx
	}
}

const (
	// InfiniteProgress is used with UpdateProgress to show progress without setting a percentage.
	InfiniteProgress = -1.0
)
