package machineenrollment

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Codes the enrollment service sets on an enrollment error, for those a machine needs to tell
// apart from others with the same status.
const (
	CodeMachineNotRegistered = "machine_not_registered"
	CodeIdentifiersAmbiguous = "identifiers_ambiguous"
	CodeMachineDeprovisioned = "machine_deprovisioned"
	CodeMachineEnrolled      = "machine_enrolled"
	CodeMachineRegistering   = "machine_registering"
)

// Errors for the typed enrollment errors, for use with errors.Is.
var (
	// ErrMachineNotRegistered: no machine the fleet key allows has any of the identifiers.
	ErrMachineNotRegistered = &EnrollmentError{Code: CodeMachineNotRegistered}
	// ErrIdentifiersAmbiguous: the identifiers name more than one machine the fleet key allows.
	ErrIdentifiersAmbiguous = &EnrollmentError{Code: CodeIdentifiersAmbiguous}
	// ErrMachineDeprovisioned: the machine is retired and can't enroll again.
	ErrMachineDeprovisioned = &EnrollmentError{Code: CodeMachineDeprovisioned}
	// ErrMachineEnrolled: a fleet key can't enroll a machine that has an active client. An admin has to
	// issue a device token to re-enroll it.
	ErrMachineEnrolled = &EnrollmentError{Code: CodeMachineEnrolled}
	// ErrMachineRegistering: another enrollment registered the machine meanwhile. The enrollment can be
	// retried.
	ErrMachineRegistering = &EnrollmentError{Code: CodeMachineRegistering}
)

// hints say what to do about an error code.
var hints = map[string]string{
	CodeMachineNotRegistered: "ask an admin to register the machine with one of its identifiers and allow the fleet key for it",
	CodeIdentifiersAmbiguous: "ask an admin which machine holds which identifier",
	CodeMachineDeprovisioned: "the machine is retired and can't enroll again",
	CodeMachineEnrolled:      "the machine is enrolled already: ask an admin for a device token to enroll it again",
	CodeMachineRegistering:   "retry the enrollment",
}

// EnrollmentError is an error response of the enrollment service. Match one of the typed
// errors, such as ErrMachineEnrolled, with errors.Is, or read the status and code with errors.As.
type EnrollmentError struct {
	// Status is the HTTP status of the response.
	Status int
	// Code tells apart errors with the same status, or is empty. See the Code constants.
	Code   string
	Detail string
	// Identifiers are those the service looked up, for CodeMachineNotRegistered.
	Identifiers []Identifier

	method, path string
}

// Error describes the response, and what to do about it if that is known.
func (e *EnrollmentError) Error() string {
	var b strings.Builder
	if e.method != "" {
		fmt.Fprintf(&b, "%s %s returned %d", e.method, e.path, e.Status)
	} else {
		fmt.Fprintf(&b, "enrollment failed with %d", e.Status)
	}
	if e.Code != "" {
		fmt.Fprintf(&b, " (%s)", e.Code)
	}
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	if hint := hints[e.Code]; hint != "" {
		b.WriteString(" (" + hint + ")")
	}
	return b.String()
}

// Is matches the typed errors by code.
func (e *EnrollmentError) Is(target error) bool {
	t, ok := target.(*EnrollmentError)
	return ok && t.Code != "" && t.Code == e.Code
}

// newEnrollmentError builds the error for a response with an unexpected status from the JSON:API
// error document in body, which may be malformed.
func newEnrollmentError(method, path string, status int, body []byte) *EnrollmentError {
	e := &EnrollmentError{Status: status, method: method, path: path}
	var res struct {
		Errors []struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
			Meta   struct {
				Identifiers []Identifier `json:"identifiers"`
			} `json:"meta"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &res) != nil {
		return e
	}
	var details []string
	for _, item := range res.Errors {
		if e.Code == "" {
			e.Code = item.Code
		}
		if e.Identifiers == nil {
			e.Identifiers = item.Meta.Identifiers
		}
		if item.Detail != "" {
			details = append(details, item.Detail)
		}
	}
	e.Detail = strings.Join(details, "; ")
	return e
}
