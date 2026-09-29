package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	AUTH_TYPE_MACHINE = "machine"
	// DPOP_HEADER carries the proof of possession signed by the machine's private key (RFC 9449).
	DPOP_HEADER = "DPoP"
)

// IdentityMode selects which identity the network stack presents to the Snyk API.
type IdentityMode string

const (
	// IdentityModeUser authenticates as the person, with an OAuth token, PAT or API token.
	IdentityModeUser IdentityMode = "user"
	// IdentityModeMachine authenticates as the machine, with its client certificate and a DPoP proof.
	IdentityModeMachine IdentityMode = "machine"
)

// ErrMachineIdentityUnavailable is returned when machine identity was requested but no usable
// MachineIdentitySource has been registered. Requests fail rather than falling back to user credentials.
var ErrMachineIdentityUnavailable = errors.New("machine identity requested but no machine identity is available")

// MachineIdentitySource is implemented by the host (a daemon, an extension, an IDE) that owns the
// machine's key material. The framework only ever asks for a certificate or a signed proof, so the
// private key never crosses this boundary.
type MachineIdentitySource interface {
	// MachineID returns the identifier of the joined machine, or an empty string before a join.
	MachineID() string
	// ClientCertificate returns the certificate presented during the TLS handshake (mutual TLS).
	ClientCertificate() (*tls.Certificate, error)
	// SignProof returns a compact JWS DPoP proof bound to the HTTP method and target URL.
	SignProof(method, url string) (string, error)
}

// IdentityModeFromConfiguration reads the configured identity mode, defaulting to user for
// unknown or empty values.
func IdentityModeFromConfiguration(config configuration.Configuration) IdentityMode {
	mode := IdentityMode(strings.ToLower(strings.TrimSpace(config.GetString(configuration.IDENTITY_MODE))))
	if mode == IdentityModeMachine {
		return IdentityModeMachine
	}
	return IdentityModeUser
}

var _ Authenticator = (*machineIdentityAuthenticator)(nil)

type machineIdentityAuthenticator struct {
	source MachineIdentitySource
}

// NewMachineIdentityAuthenticator returns an Authenticator backed by the given source.
// A nil source yields an authenticator that reports IsSupported false and fails every request.
func NewMachineIdentityAuthenticator(source MachineIdentitySource) Authenticator {
	return &machineIdentityAuthenticator{source: source}
}

// Authenticate verifies that a machine identity is present. Joining a machine is owned by the
// host's join workflow, not by the framework, so nothing is enrolled here.
func (m *machineIdentityAuthenticator) Authenticate() error {
	if !m.IsSupported() {
		return ErrMachineIdentityUnavailable
	}
	return nil
}

// AddAuthenticationHeader attaches a DPoP proof for this request. The certificate half of the
// identity is presented by the TLS layer, see networking.NetworkAccess.SetMachineIdentitySource.
func (m *machineIdentityAuthenticator) AddAuthenticationHeader(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil")
	}
	if !m.IsSupported() {
		return ErrMachineIdentityUnavailable
	}

	proof, err := m.source.SignProof(request.Method, dpopTargetURI(request))
	if err != nil {
		return fmt.Errorf("failed to sign machine identity proof: %w", err)
	}

	request.Header.Set(DPOP_HEADER, proof)
	return nil
}

func (m *machineIdentityAuthenticator) IsSupported() bool {
	return m.source != nil && len(m.source.MachineID()) > 0
}

// dpopTargetURI is the htu claim: the request URL without query and fragment.
func dpopTargetURI(request *http.Request) string {
	if request.URL == nil {
		return ""
	}
	u := *request.URL
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}
