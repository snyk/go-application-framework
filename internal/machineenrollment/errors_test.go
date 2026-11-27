package machineenrollment

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnrollmentErrorParsesTheErrorDocument(t *testing.T) {
	body := `{"jsonapi":{"version":"1.0"},"errors":[{"status":"403","code":"machine_not_registered","title":"Forbidden","detail":"No machine has these.","meta":{"identifiers":[{"type":"serial_number","value":"C02"}]}}]}`

	err := newEnrollmentError("POST", "/hidden/machines/enrollments", 403, []byte(body))

	assert.Equal(t, 403, err.Status)
	assert.Equal(t, CodeMachineNotRegistered, err.Code)
	assert.Equal(t, "No machine has these.", err.Detail)
	assert.Equal(t, []Identifier{{Type: "serial_number", Value: "C02"}}, err.Identifiers)
	assert.ErrorIs(t, err, ErrMachineNotRegistered)
	assert.NotErrorIs(t, err, ErrMachineEnrolled)
	assert.Equal(t, "POST /hidden/machines/enrollments returned 403 (machine_not_registered): No machine has these.", err.Error())
}

func TestNewEnrollmentErrorToleratesOtherBodies(t *testing.T) {
	for _, body := range []string{"", "not json", `{"errors":[]}`, `<html>`} {
		err := newEnrollmentError("POST", "/p", 502, []byte(body))
		assert.Equal(t, 502, err.Status, body)
		assert.Empty(t, err.Code, body)
		assert.Equal(t, "POST /p returned 502", err.Error(), body)
		assert.False(t, errors.Is(err, ErrMachineEnrolled), body)
	}
}

func TestEnrollmentErrorWithoutACodeMatchesNoSentinel(t *testing.T) {
	err := error(&EnrollmentError{Status: 401})
	for _, target := range []error{ErrMachineNotRegistered, ErrIdentifiersAmbiguous, ErrMachineDeprovisioned, ErrMachineEnrolled} {
		assert.NotErrorIs(t, err, target)
	}
}

func TestEnrollmentErrorHints(t *testing.T) {
	for _, code := range []string{CodeMachineNotRegistered, CodeIdentifiersAmbiguous, CodeMachineDeprovisioned, CodeMachineEnrolled} {
		require.NotEmpty(t, hints[code], code)
	}
	assert.Contains(t, (&EnrollmentError{Status: 409, Code: CodeMachineEnrolled}).Error(), "device token")
}

func TestNewEnrollmentErrorBoundsTheDetail(t *testing.T) {
	body := `{"errors":[{"detail":"` + strings.Repeat("ü", 35*1024) + `"}]}`

	err := newEnrollmentError("POST", "/p", 500, []byte(body))

	assert.LessOrEqual(t, len(err.Detail), 512+len("…"))
	assert.True(t, utf8.ValidString(err.Detail), "cut on a rune boundary")
	assert.True(t, strings.HasSuffix(err.Detail, "…"))
}

func TestNewEnrollmentErrorStripsControlCharactersAndEscapes(t *testing.T) {
	body := `{"errors":[{"code":"\u001b[31mmachine_enrolled\u001b[0m","detail":"\u001b[31mred\u001b[0m\r\nline\u0007\u0000\u0085\u202eend\ttab"}]}`

	err := newEnrollmentError("POST", "/p", 500, []byte(body))

	assert.Equal(t, "red lineend tab", err.Detail)
	assert.Equal(t, CodeMachineEnrolled, err.Code)
}

func TestEnrollmentErrorHintOnlyWithoutADetail(t *testing.T) {
	withDetail := newEnrollmentError("POST", "/p", 409, []byte(`{"errors":[{"code":"machine_enrolled","detail":"The machine is enrolled already. Ask an admin for a device token to enroll it again."}]}`))
	withoutDetail := newEnrollmentError("POST", "/p", 409, []byte(`{"errors":[{"code":"machine_enrolled"}]}`))

	assert.Equal(t, "POST /p returned 409 (machine_enrolled): The machine is enrolled already. Ask an admin for a device token to enroll it again.", withDetail.Error())
	assert.Equal(t, "POST /p returned 409 (machine_enrolled) ("+hints[CodeMachineEnrolled]+")", withoutDetail.Error())
}
