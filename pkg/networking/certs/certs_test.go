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
	file, err := os.CreateTemp(t.TempDir(), "")
	defer func() { _ = file.Close() }()
	assert.NoError(t, err)
	_, err = file.Write([]byte{'h', 'e', 'l', 'l', 'o'})
	assert.NoError(t, err)

	extraCertificateBytes, extraCertificateList, extraCertificateError := GetExtraCaCert(file.Name())
	fmt.Println(string(extraCertificateBytes))
	assert.Empty(t, extraCertificateList)
	assert.Empty(t, extraCertificateBytes)
	assert.NotNil(t, extraCertificateError)
}

func Test_GetExtraCaCert_CertSpecified(t *testing.T) {
	logger := log.Default()
	certPem, _, err := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	assert.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "")
	defer func() { _ = file.Close() }()
	assert.NoError(t, err)
	_, err = file.Write(certPem)
	assert.NoError(t, err)

	extraCertificateBytes, extraCertificateList, extraCertificateError := GetExtraCaCert(file.Name())
	assert.Len(t, extraCertificateList, 1)
	assert.NotEmpty(t, extraCertificateBytes)
	assert.NoError(t, extraCertificateError)
}

func Test_AppendExtraCaCert_AddOneCert(t *testing.T) {
	logger := log.Default()
	extraCertPem, _, err := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	assert.NoError(t, err)
	certPem, _, err := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	assert.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "")
	defer func() { _ = file.Close() }()
	assert.NoError(t, err)
	_, err = file.Write(extraCertPem)
	assert.NoError(t, err)

	certPem = AppendExtraCaCert(file.Name(), certPem)

	certList, err := GetAllCerts(certPem)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(certList))
}

func Test_AppendExtraCaCert_AddNoCert(t *testing.T) {
	logger := log.Default()
	extraCertPem := "djalks"
	certPem, _, err := MakeSelfSignedCert("mycert", []string{"dns"}, logger)
	assert.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "")
	defer func() { _ = file.Close() }()
	assert.NoError(t, err)
	_, err = file.Write([]byte(extraCertPem))
	assert.NoError(t, err)

	certPem = AppendExtraCaCert(file.Name(), certPem)

	certList, err := GetAllCerts(certPem)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(certList))
}
