package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

func ApplyTlsConfig(transport *http.Transport, insecure bool, caPool *x509.CertPool) *http.Transport {
	transport = transport.Clone()

	// Initialize TLSClientConfig if it is nil
	// This is needed to avoid nil pointer dereference
	// Which may happen if the transport is cloned from a default transport
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = insecure
	transport.TLSClientConfig.RootCAs = caPool
	return transport
}
