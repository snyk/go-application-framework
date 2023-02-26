package networking

import (
	"fmt"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func Test_Authenticate(t *testing.T) {
	config := configuration.New()
	networkAccess := NewNetworkAccess(config)
	httpClient := networkAccess.GetHttpClient()

	oAuth2Authenticator := NewOAuth2Authenticator(config, httpClient)

	err := oAuth2Authenticator.Authenticate()
	assert.Nil(t, err)
	fmt.Println(config.GetString(CONFIG_KEY_OAUTH_TOKEN))
}
