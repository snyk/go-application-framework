package machineenrollment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIoregSerial(t *testing.T) {
	output := `+-o Root  <class IORegistryEntry>
  +-o MacBookPro  <class IOPlatformExpertDevice>
    {
      "IOPlatformUUID" = "11111111-2222-3333-4444-555555555555"
      "IOPlatformSerialNumber" = "C02XK1JHJG5J"
      "manufacturer" = <"Apple Inc.">
    }
`
	assert.Equal(t, "C02XK1JHJG5J", parseIoregSerial(output))
	assert.Empty(t, parseIoregSerial("nothing here"))
}

func TestSerialIdentifiers(t *testing.T) {
	got := serialIdentifiers([]string{" ABC123\n", "To Be Filled By O.E.M.", "", "None", "ABC123", "Default string", "BOARD-7", "0"})

	assert.Equal(t, []Identifier{
		{Type: "serial_number", Value: "ABC123"},
		{Type: "serial_number", Value: "BOARD-7"},
	}, got)
}

func TestSerialIdentifiersCapsAtTheServerLimit(t *testing.T) {
	var serials []string
	for i := range 40 {
		serials = append(serials, strings.Repeat("S", 1+i))
	}
	assert.Len(t, serialIdentifiers(serials), maxIdentifiers)
}

func TestSerialNumbersOfThisPlatform(t *testing.T) {
	ids, err := SerialNumbers(t.Context())
	if err != nil {
		t.Skipf("no serial number readable here: %v", err)
	}
	require.NotEmpty(t, ids)
	assert.Equal(t, IdentifierTypeSerialNumber, ids[0].Type)
	assert.NotEmpty(t, ids[0].Value)
	assert.NoError(t, validateIdentifiers(ids))
}

func TestReadDMISerials(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "product_serial"), []byte("P-1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chassis_serial"), []byte("Not Specified\n"), 0o600))

	got := serialIdentifiers(readDMISerials(dir))

	assert.Equal(t, []Identifier{{Type: "serial_number", Value: "P-1"}}, got)
}
