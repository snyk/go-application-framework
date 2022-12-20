package certs

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetExtraCaCert_NoCertSpecified(t *testing.T) {
	extraCertificateBytes, extraCertificateList, extraCertificateError := GetExtraCaCert("")
	assert.Empty(t, extraCertificateList)
	assert.Empty(t, extraCertificateBytes)
	assert.Nil(t, extraCertificateError)
}

func Test_GetExtraCaCert_InvalidPathSpecified(t *testing.T) {
	extraCertificateBytes, extraCertificateList, extraCertificateError := GetExtraCaCert("not extsing file")
	assert.Empty(t, extraCertificateList)
	assert.Empty(t, extraCertificateBytes)
	assert.NotNil(t, extraCertificateError)
}

func Test_GetExtraCaCert_InvalidCertSpecified(t *testing.T) {
	file, _ := os.CreateTemp("", "")
	file.Write([]byte{'h', 'e', 'l', 'l', 'o'})

	extraCertificateBytes, extraCertificateList, extraCertificateError := GetExtraCaCert(file.Name())
	fmt.Println(string(extraCertificateBytes))
	assert.Empty(t, extraCertificateList)
	assert.Empty(t, extraCertificateBytes)
	assert.NotNil(t, extraCertificateError)

	// cleanup
	os.Remove(file.Name())
}

func Test_GetExtraCaCert_CertSpecified(t *testing.T) {
	logger := log.Default()
	certPem, _, _ := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	file, _ := os.CreateTemp("", "")
	file.Write(certPem)

	extraCertificateBytes, extraCertificateList, extraCertificateError := GetExtraCaCert(file.Name())
	assert.Len(t, extraCertificateList, 1)
	assert.NotEmpty(t, extraCertificateBytes)
	assert.Nil(t, extraCertificateError)

	// cleanup
	os.Remove(file.Name())
}

func Test_AppendExtraCaCert_AddOneCert(t *testing.T) {
	logger := log.Default()
	extraCertPem, _, _ := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	certPem, _, _ := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	file, _ := os.CreateTemp("", "")
	file.Write(extraCertPem)

	certPem = AppendExtraCaCert(file.Name(), certPem)

	certList, err := GetAllCerts(certPem)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(certList))

	// cleanup
	os.Remove(file.Name())
}

func Test_AppendExtraCaCert_AddNoCert(t *testing.T) {
	logger := log.Default()
	extraCertPem := "djalks"
	certPem, _, _ := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	file, _ := os.CreateTemp("", "")
	file.Write([]byte(extraCertPem))

	certPem = AppendExtraCaCert(file.Name(), certPem)

	certList, err := GetAllCerts(certPem)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(certList))

	// cleanup
	os.Remove(file.Name())
}
