package configuration

import "errors"

// ErrMissingOrganization is returned by Resolve when an org-scoped setting is resolved
// but no ORGANIZATION is set in the configuration.
var ErrMissingOrganization = errors.New("organization is required: set '" + ORGANIZATION + "' before calling Resolve on an org-scoped setting")

// ErrMissingInputDirectory is returned by Resolve when an org- or folder-scoped setting
// is resolved but INPUT_DIRECTORY is not set or is empty in the configuration.
var ErrMissingInputDirectory = errors.New("input directory is required: set '" + INPUT_DIRECTORY + "' before calling Resolve on a folder- or org-scoped setting")
