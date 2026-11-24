package osname

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseOSRelease(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "pretty name",
			content: "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n",
			want:    "Ubuntu 22.04.4 LTS",
		},
		{
			name:    "name and version id without pretty name",
			content: "NAME=Alpine\nVERSION_ID=3.19.1\n",
			want:    "Alpine 3.19.1",
		},
		{
			name:    "name only",
			content: "NAME='Arch Linux'\n",
			want:    "Arch Linux",
		},
		{
			name:    "comments and blank lines",
			content: "# comment\n\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
			want:    "Debian GNU/Linux 12 (bookworm)",
		},
		{
			name:    "empty pretty name falls back",
			content: "PRETTY_NAME=\"\"\nNAME=Fedora\nVERSION_ID=40\n",
			want:    "Fedora 40",
		},
		{
			name:    "version id without name uses the default name",
			content: "VERSION_ID=3.19\n",
			want:    "Linux 3.19",
		},
		{
			name:    "nothing usable",
			content: "ID=unknown\n",
			want:    "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseOSRelease([]byte(tc.content)))
		})
	}
}

func Test_Get_namesTheRunningOperatingSystem(t *testing.T) {
	prefixes := map[string]string{"darwin": "macOS ", "linux": "", "windows": "Windows "}
	prefix, supported := prefixes[runtime.GOOS]
	if !supported {
		t.Skipf("no detection for %s", runtime.GOOS)
	}

	name := Get()

	assert.NotEmpty(t, name)
	assert.True(t, strings.HasPrefix(name, prefix), "got %q", name)
}

func Test_windowsName(t *testing.T) {
	testCases := []struct {
		name        string
		major       uint32
		minor       uint32
		build       uint32
		workstation bool
		want        string
	}{
		{"windows 11", 10, 0, 22631, true, "Windows 11 10.0.22631"},
		{"first windows 11 build", 10, 0, 22000, true, "Windows 11 10.0.22000"},
		{"windows 10", 10, 0, 19045, true, "Windows 10 10.0.19045"},
		{"windows server", 10, 0, 20348, false, "Windows Server 10.0.20348"},
		{"windows 8.1", 6, 3, 9600, true, "Windows 6.3.9600"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, windowsName(tc.major, tc.minor, tc.build, tc.workstation))
		})
	}
}
