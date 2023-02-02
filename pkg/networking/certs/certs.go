package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

// MakeSelfSignedCert creates a self-signed certificate and returns it as a PEM encoded byte slice
func MakeSelfSignedCert(certName string, dnsNames []string, debugLogger *log.Logger) (certPEMBlock []byte, keyPEMBlock []byte, err error) {
	// create a key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// create a self-signed cert using the key
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: certName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageCertSign, // needed for sure

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, dnsName := range dnsNames {
		template.DNSNames = append(template.DNSNames, dnsName)
		debugLogger.Println("MakeSelfSignedCert added ", dnsName)
	}

	certDERBytes, err_CreateCertificate := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err_CreateCertificate != nil {
		return nil, nil, err
	}

	certPEMBytesBuffer := &bytes.Buffer{}
	if err := pem.Encode(certPEMBytesBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes}); err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	// make the key pem
	keyDERBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEMBytesBuffer := &bytes.Buffer{}
	if err := pem.Encode(keyPEMBytesBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDERBytes}); err != nil {
		return nil, nil, err
	}

	certPEMBlockBytes := certPEMBytesBuffer.Bytes()
	keyPEMBlockBytes := keyPEMBytesBuffer.Bytes()

	return certPEMBlockBytes, keyPEMBlockBytes, nil
}

// Append all certificates specified via extraCertificateLocation to the given PEM formatted byte slice
func AppendExtraCaCert(extraCertificateLocation string, certPem []byte) []byte {
	// try to access certificate file provided via the environment variable extraCertificateLocation
	extraCertificateBytes, _, extraCertificateError := GetExtraCaCert(extraCertificateLocation)
	if extraCertificateError == nil {
		certPem = append(certPem, '\n')
		certPem = append(certPem, extraCertificateBytes...)
	}
	return certPem
}

// Returns the Certificates specified via extraCertificateLocation as a PEM formatted byte slice and as a list of certificates.
func GetExtraCaCert(extraCertificateLocation string) ([]byte, []*x509.Certificate, error) {
	var resultAsByte []byte
	var err error
	var resultAsCert []*x509.Certificate

	if len(extraCertificateLocation) > 0 {
		resultAsByte, err = os.ReadFile(extraCertificateLocation)
	} else {
		return resultAsByte, resultAsCert, err
	}

	// check if the cert file is a valid PEM content
	if err == nil {
		resultAsCert, err = GetAllCerts(resultAsByte)
	}

	if err != nil {
		resultAsByte = nil
		resultAsCert = nil
	}

	return resultAsByte, resultAsCert, err
}

// Decode all Certifactes given in the PEM formatted input slice and return the Certificates as a list. It returns an error if any of the content is not a Certificate.
func GetAllCerts(pemData []byte) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	for len(pemData) > 0 {
		var b *pem.Block
		b, pemData = pem.Decode(pemData)

		if b == nil && len(pemData) > 0 {
			return nil, fmt.Errorf("data contains non certificate")
		} else if b == nil {
			break
		}

		if strings.ToLower(b.Type) != "certificate" {
			return nil, fmt.Errorf("data contains non certificate")
		}

		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}

		result = append(result, cert)
	}

	return result, nil
}

// Get global Certificate pool including x509.SystemCertPool() + extraCertificateLocation
func AddCertificatesToPool(pool *x509.CertPool, extraCertificateLocation string) error {

	_, extracCertList, err := GetExtraCaCert(extraCertificateLocation)
	if err != nil {
		return err
	}

	// append extra ca certificates if specified
	for _, currentCert := range extracCertList {
		if currentCert != nil {
			pool.AddCert(currentCert)
		}
	}

	return err
}
