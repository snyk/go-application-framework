package machineenrollment

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSelectCertificate(t *testing.T) {
	now := time.Now()
	accepted := []byte("accepted issuer")
	cert := func(issuer string, notBefore, notAfter time.Time, usages ...x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{RawIssuer: []byte(issuer), NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: usages}
	}
	valid := func(notAfter time.Duration, usages ...x509.ExtKeyUsage) *x509.Certificate {
		return cert(string(accepted), now.Add(-time.Hour), now.Add(notAfter), usages...)
	}

	tests := map[string]struct {
		certs []*x509.Certificate
		want  int
	}{
		"none":                 {nil, -1},
		"other issuer":         {[]*x509.Certificate{cert("other", now.Add(-time.Hour), now.Add(time.Hour))}, -1},
		"expired":              {[]*x509.Certificate{valid(-time.Minute)}, -1},
		"not yet valid":        {[]*x509.Certificate{cert(string(accepted), now.Add(time.Hour), now.Add(2*time.Hour))}, -1},
		"server auth only":     {[]*x509.Certificate{valid(time.Hour, x509.ExtKeyUsageServerAuth)}, -1},
		"client auth":          {[]*x509.Certificate{valid(time.Hour, x509.ExtKeyUsageClientAuth)}, 0},
		"no extended usages":   {[]*x509.Certificate{valid(time.Hour)}, 0},
		"unparseable skipped":  {[]*x509.Certificate{nil, valid(time.Hour)}, 1},
		"latest expiry wins":   {[]*x509.Certificate{valid(time.Hour), valid(48 * time.Hour), valid(2 * time.Hour)}, 1},
		"only accepted counts": {[]*x509.Certificate{cert("other", now.Add(-time.Hour), now.Add(72*time.Hour)), valid(time.Hour)}, 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, selectCertificate(tc.certs, [][]byte{accepted}, now))
		})
	}
}
