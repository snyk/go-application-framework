//go:build !unix

package configuration

import "io/fs"

func matchOwner(string, fs.FileInfo) {}
