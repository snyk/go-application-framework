package machineenrollment

import (
	"errors"
	"testing"

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
	assert.Contains(t, err.Error(), "POST /hidden/machines/enrollments returned 403 (machine_not_registered): No machine has these.")
	assert.Contains(t, err.Error(), "ask an admin to register the machine")
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

func TestKeyNotSavedErrorIdentifiesTheEnrolledClient(t *testing.T) {
	cause := errors.New("failed replacing machine client key file: permission denied")
	err := &KeyNotSavedError{
		ClientID:  "client-9",
		MachineID: "machine-9",
		KeyPath:   "/tmp/key.pem.123.tmp",
		DestPath:  "/tmp/key.pem",
		Err:       cause,
	}

	assert.ErrorIs(t, err, ErrKeyNotSaved)
	assert.ErrorIs(t, err, cause)
	msg := err.Error()
	assert.Contains(t, msg, "client_id client-9")
	assert.Contains(t, msg, "machine-9")
	assert.Contains(t, msg, "/tmp/key.pem.123.tmp")
	assert.Contains(t, msg, CONFIG_KEY_CLIENT_ID+" to client-9")
	assert.Contains(t, msg, CONFIG_KEY_MACHINE_ID+" to machine-9")
	assert.Contains(t, msg, "do not enroll again")
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
