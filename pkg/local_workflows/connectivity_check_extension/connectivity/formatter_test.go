package connectivity

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ====================================
// User Information Tests
// ====================================

func Test_Formatter_FormatResult_UserInfo(t *testing.T) {
	result := &ConnectivityCheckResult{
		CurrentUser: "testuser",
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Current User Information")
	assert.Contains(t, output, "Username: testuser")
}

func Test_Formatter_FormatResult_EmptyCurrentUser(t *testing.T) {
	result := &ConnectivityCheckResult{
		CurrentUser: "",
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Current User Information")
	assert.Contains(t, output, "Unable to determine current username")
}

// ====================================
// Single Directory Tests
// ====================================

func Test_Formatter_FormatResult_WriteableDirectoryWithBinary(t *testing.T) {
	dirPath := "/some/path/snyk"
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    dirPath,
				PathFound:     dirPath,
				Purpose:       "Test Directory",
				MayContainCLI: true,
				IsWritable:    true,
				Permissions:   "0750",
				BinariesFound: []BinaryInfo{
					{
						Name:        "snyk-linux",
						Permissions: "0755",
					},
				},
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Potential Snyk Used Configuration and CLI Download Directories")
	assert.Contains(t, output, "Directory: "+dirPath+" (Purpose: Test Directory)")
	assert.Contains(t, output, "Exists")
	assert.Contains(t, output, "Writable")
	assert.Contains(t, output, "(permissions: 0750)")
	assert.Contains(t, output, "Found 1 potential Snyk CLI binary/binaries:")
	assert.Contains(t, output, "snyk-linux")
	assert.Contains(t, output, "(permissions: 0755)")
}

func Test_Formatter_FormatResult_DirectoryWithMultipleBinaries(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/usr/local/bin",
				Purpose:       "System Binaries",
				MayContainCLI: true,
				PathFound:     "/usr/local/bin",
				IsWritable:    true,
				Permissions:   "0750",
				BinariesFound: []BinaryInfo{
					{
						Name:        "snyk-linux",
						Permissions: "0755",
					},
					{
						Name:        "snyk-macos",
						Permissions: "0777",
					},
				},
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Directory: /usr/local/bin (Purpose: System Binaries)")
	assert.Contains(t, output, "Exists")
	assert.Contains(t, output, "Found 2 potential Snyk CLI binary/binaries:")
	assert.Contains(t, output, "• snyk-linux")
	assert.Contains(t, output, "(permissions: 0755)")
	assert.Contains(t, output, "• snyk-macos")
	assert.Contains(t, output, "(permissions: 0777)")
}

func Test_Formatter_FormatResult_DirectoryExistsWithNoBinaries(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/home/testuser/.snyk",
				Purpose:       "User Snyk Directory",
				MayContainCLI: true,
				PathFound:     "/home/testuser/.snyk",
				IsWritable:    true,
				Permissions:   "0755",
				BinariesFound: []BinaryInfo{},
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Directory: /home/testuser/.snyk (Purpose: User Snyk Directory)")
	assert.Contains(t, output, "Exists")
	assert.Contains(t, output, "Writable")
	assert.Contains(t, output, "No Snyk CLI binaries found")
}

func Test_Formatter_FormatResult_ConfigDirectoryNoCLICheck(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/home/testuser/.config/snyk",
				Purpose:       "Language Server Config Storage",
				MayContainCLI: false,
				PathFound:     "/home/testuser/.config/snyk",
				IsWritable:    true,
				Permissions:   "0755",
				BinariesFound: []BinaryInfo{},
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Directory: /home/testuser/.config/snyk (Purpose: Language Server Config Storage)")
	assert.Contains(t, output, "Exists")
	assert.Contains(t, output, "Writable")
	assert.NotContains(t, output, "No Snyk CLI binaries found")
	assert.NotContains(t, output, "Found")
}

func Test_Formatter_FormatResult_DirectoryDoesNotExist(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:  "/home/testuser/.snyk/cli",
				Purpose:     "Test CLI Directory",
				PathFound:   "/home/testuser",
				IsWritable:  true,
				Permissions: "0755",
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Directory: /home/testuser/.snyk/cli (Purpose: Test CLI Directory)")
	assert.Contains(t, output, "Does not exist")
	assert.Contains(t, output, "Nearest existing parent: /home/testuser")
	assert.Contains(t, output, "Writable")
}

func Test_Formatter_FormatResult_ParentDirectoryNotWritable(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:  "/root/.snyk",
				Purpose:     "Root CLI Directory",
				PathFound:   "/root",
				IsWritable:  false,
				Permissions: "0700",
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Directory: /root/.snyk (Purpose: Root CLI Directory)")
	assert.Contains(t, output, "Does not exist")
	assert.Contains(t, output, "Nearest existing parent: /root")
	assert.Contains(t, output, "Not writable")
	assert.Contains(t, output, "(permissions: 0700)")
}

func Test_Formatter_FormatResult_DirectoryCheckError(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted: "/some/path",
				Purpose:    "Error Test Directory",
				PathFound:  "",
				Error:      "permission denied",
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Directory: /some/path (Purpose: Error Test Directory)")
	assert.Contains(t, output, "Error: permission denied")
}

// ====================================
// Special Case Directory Tests
// ====================================

func Test_Formatter_FormatResult_MultipleDirectoriesWithVariedStatuses(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:  "/home/testuser/.snyk",
				Purpose:     "User Directory",
				PathFound:   "/home/testuser/.snyk",
				IsWritable:  true,
				Permissions: "0755",
			},
			{
				PathWanted:  "/usr/local/bin/snyk",
				Purpose:     "System Binary",
				PathFound:   "/usr/local/bin",
				IsWritable:  true,
				Permissions: "0755",
			},
			{
				PathWanted:  "/opt/snyk",
				Purpose:     "Optional Directory",
				PathFound:   "/opt",
				IsWritable:  false,
				Permissions: "0755",
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()

	// Verify all directories are shown with their full labels
	assert.Contains(t, output, "Directory: /home/testuser/.snyk (Purpose: User Directory)")
	assert.Contains(t, output, "Directory: /usr/local/bin/snyk (Purpose: System Binary)")
	assert.Contains(t, output, "Directory: /opt/snyk (Purpose: Optional Directory)")

	// Verify first directory exists and is writable
	assert.Contains(t, output, "Exists")

	// Verify second directory doesn't exist but parent is writable
	assert.Contains(t, output, "Does not exist")
	assert.Contains(t, output, "Nearest existing parent: /usr/local/bin")

	// Verify third directory parent is not writable
	assert.Contains(t, output, "Nearest existing parent: /opt")
	assert.Contains(t, output, "Not writable")
}

func Test_Formatter_FormatResult_NoDirectories(t *testing.T) {
	result := &ConnectivityCheckResult{
		DirectoryResults: []DirectoryCheckResult{},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Potential Snyk Used Configuration and CLI Download Directories")
	assert.Contains(t, output, "No directories checked")
}

// ====================================
// Generic Special Cases
// ====================================

func Test_Formatter_FormatResult_ColorOutputEnabled(t *testing.T) {
	result := &ConnectivityCheckResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:  "/home/testuser/.snyk",
				Purpose:     "Color Test Directory",
				PathFound:   "/home/testuser/.snyk",
				IsWritable:  true,
				Permissions: "0755",
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, true)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	// When colors are enabled, output should contain ANSI escape codes
	// We just verify that the content is there, not the exact ANSI codes
	assert.Contains(t, output, "Current User Information")
	assert.Contains(t, output, "Username: testuser")
	assert.Contains(t, output, "Directory: /home/testuser/.snyk (Purpose: Color Test Directory)")
}
