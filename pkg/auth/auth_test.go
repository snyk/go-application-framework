package auth

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_Authenticate(t *testing.T) {
	config := configuration.New()
	Authenticate()
}
