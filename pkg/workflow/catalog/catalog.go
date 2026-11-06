// Package catalog lets workflows label themselves, and lets applications find workflows by label.
//
// A label is a string pair such as lifecycle=install, stored in the entry metadata under the prefix "label:".
//
// Label rules:
//   - One value per label: repeating a label option keeps the last value.
//   - Labels are set at registration and cannot change afterwards.
//   - Label names use lowercase letters, digits, dots and dashes, and start and end with a letter or digit.
package catalog

import (
	"errors"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const labelPrefix = "label:"

const lifecycleLabel = "lifecycle"

type Lifecycle string

const (
	Install   Lifecycle = "install"
	Uninstall Lifecycle = "uninstall"
)

// ErrMetadataUnsupported is returned by Register when labels are requested but the entry does not support metadata.
// The workflow stays registered without labels.
var ErrMetadataUnsupported = errors.New("workflow entry does not support metadata")

type RegisterOption func(labels map[string]string)

func WithLifecycle(lifecycle Lifecycle) RegisterOption {
	return func(labels map[string]string) {
		labels[lifecycleLabel] = string(lifecycle)
	}
}

// Without options it behaves exactly like engine.Register, and its errors are returned unchanged. If the entry does not
// support metadata, it returns the entry together with ErrMetadataUnsupported.
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
