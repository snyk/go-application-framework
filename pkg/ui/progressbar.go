package ui

import "github.com/snyk/go-application-framework/pkg/ui/consoleui"

// ProgressType aliases for backward compatibility
type ProgressType = consoleui.ProgressType

const (
	SpinnerType ProgressType = consoleui.SpinnerType
	BarType     ProgressType = consoleui.BarType
)
