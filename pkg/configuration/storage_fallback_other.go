//go:build !unix && !windows

package configuration

import (
	"errors"
	"io/fs"
)

func canFallBack(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}
