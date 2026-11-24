//go:build !darwin && !linux && !windows

package osname

func detect() string {
	return ""
}
