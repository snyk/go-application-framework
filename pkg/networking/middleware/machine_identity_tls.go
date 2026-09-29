package middleware

import (
	"crypto/tls"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
)

// ApplyMachineIdentityTlsConfig presents the machine's client certificate during the TLS
// handshake. The certificate is fetched per handshake so a renewed certificate is picked up
// without rebuilding the transport, and the private key stays inside the source.
func ApplyMachineIdentityTlsConfig(transport *http.Transport, source auth.MachineIdentitySource, logger *zerolog.Logger) *http.Transport {
	if source == nil {
		return transport
	}

	transport = transport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	transport.TLSClientConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := source.ClientCertificate()
		if err != nil {
			if logger != nil {
				logger.Warn().Err(err).Msg("machine identity client certificate unavailable")
			}
			return nil, err
		}
		if cert == nil {
			return &tls.Certificate{}, nil
		}
		return cert, nil
	}
	return transport
}
