package middleware

import (
	"crypto/x509"
	"net/http"
)

func ApplyTlsConfig(transport *http.Transport, insecure bool, caPool *x509.CertPool) *http.Transport {
	transport = transport.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = insecure
	transport.TLSClientConfig.RootCAs = caPool
	return transport
}
