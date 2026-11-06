// Package catalog lets workflows label themselves, and lets applications find workflows by label.
//
// A label is a string pair such as lifecycle=install, stored in the entry metadata under the reserved prefix "label:".
// The engine does not interpret labels; this package does.
//
// Label rules:
//   - One value per label. Passing the same label option twice keeps the last value.
//   - Labels are set when the workflow is registered and cannot change afterwards, because metadata values never change.
//   - Label names use lowercase letters, digits, dots and dashes, and start and end with a letter or digit.
package catalog

import (
	"errors"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

// labelPrefix is the reserved metadata key prefix for labels.
const labelPrefix = "label:"

// lifecycleLabel is the name of the predefined lifecycle label.
const lifecycleLabel = "lifecycle"

// Lifecycle is a predefined value of the lifecycle label.
type Lifecycle string

const (
	// Install labels a workflow as an install step: lifecycle=install.
	Install Lifecycle = "install"
	// Uninstall labels a workflow as an uninstall step: lifecycle=uninstall.
	Uninstall Lifecycle = "uninstall"
)

// ErrMetadataUnsupported is returned by Register when labels were requested but the entry does not support metadata.
// The workflow stays registered without labels.
var ErrMetadataUnsupported = errors.New("workflow entry does not support metadata")

// RegisterOption sets a label on a workflow when it is registered.
type RegisterOption func(labels map[string]string)

// WithLifecycle labels the workflow with lifecycle=<lifecycle>.
func WithLifecycle(lifecycle Lifecycle) RegisterOption {
	return func(labels map[string]string) {
		labels[lifecycleLabel] = string(lifecycle)
	}
}

// Register registers a workflow with the engine and labels it with the given options.
//
// Without options it behaves exactly like engine.Register. An error from engine.Register is returned unchanged,
// together with the entry that engine.Register returned, which is nil. If the entry does not support metadata,
// Register returns the entry together with ErrMetadataUnsupported; the workflow stays registered without labels.
func Register(engine workflow.Engine, id workflow.Identifier, config workflow.ConfigurationOptions, callback workflow.Callback, opts ...RegisterOption) (workflow.Entry, error) {
	entry, err := engine.Register(id, config, callback)
	if err != nil {
		return entry, err
	}

	labels := map[string]string{}
	for _, opt := range opts {
		opt(labels)
	}
	if len(labels) == 0 {
		return entry, nil
	}

	withMetadata, ok := entry.(workflow.EntryWithMetadata)
	if !ok {
		return entry, ErrMetadataUnsupported
	}
	for name, value := range labels {
		if err := withMetadata.SetMetadata(labelPrefix+name, value); err != nil {
			return entry, err
		}
	}
	return entry, nil
}
