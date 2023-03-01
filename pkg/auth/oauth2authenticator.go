package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"time"

	"github.com/pkg/browser"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"golang.org/x/oauth2"
)

const (
	CONFIG_KEY_OAUTH_TOKEN string = "OAUTH_TOKEN"
	OAUTH_CLIENT_ID        string = "0oa37b7oa3zOoDWCe4h7"
)

type oAuth2Authenticator struct {
	httpClient  *http.Client
	config      configuration.Configuration
	oauthConfig *oauth2.Config
	token       *oauth2.Token
	headless    bool
}

func getConfigration(config configuration.Configuration) *oauth2.Config {

	appUrl := config.GetString(configuration.APP_URL)
	appUrl = "https://app.fedramp-alpha.snykgov.io"

	conf := &oauth2.Config{
		ClientID: OAUTH_CLIENT_ID,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://snyk-fedramp-alpha.okta.com/oauth2/default/v1/token",
			AuthURL:  appUrl + "/oauth/authorize",
		},
		RedirectURL: "http://localhost:8080/authorization-code/callback",
	}
	return conf
}

func getCodeChallenge(verifier []byte) string {
	shasum := sha256.Sum256(verifier)
	return base64.RawURLEncoding.EncodeToString(shasum[:])
}

func createVerifier(count int) []byte {
	/*
	  unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	   ALPHA = %x41-5A / %x61-7A
	   DIGIT = %x30-39
	*/
	lut := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
	b := make([]byte, count)
	rand.Seed(time.Now().Unix())

	// TODO is this good enough?
	for i := range b {
		index := rand.Int() % len(lut)
		b[i] = lut[index]
	}

	return b
}

func getToken(config configuration.Configuration) (*oauth2.Token, error) {
	oauthTokenString := config.GetString(CONFIG_KEY_OAUTH_TOKEN)
	if len(oauthTokenString) > 0 {
		token := &oauth2.Token{}
		err := json.Unmarshal([]byte(oauthTokenString), token)
		if err != nil {
			return nil, err
		}
		return token, nil
	}
	return nil, nil
}

func NewOAuth2Authenticator(config configuration.Configuration, httpClient *http.Client) Authenticator {
	token, _ := getToken(config)
	oauthConfig := getConfigration(config)

	return &oAuth2Authenticator{
		httpClient:  httpClient,
		config:      config,
		oauthConfig: oauthConfig,
		token:       token,
	}
}

func (o *oAuth2Authenticator) IsSupported() bool {
	return o.token != nil
}

func (o *oAuth2Authenticator) persistToken(token *oauth2.Token) {
	tokenstring, _ := json.Marshal(token)
	o.config.Set(CONFIG_KEY_OAUTH_TOKEN, string(tokenstring))
	o.token = token
}

func (o *oAuth2Authenticator) Authenticate() error {
	var responseCode string
	var responseState string
	var responseError string
	verifier := createVerifier(128)
	state := string(createVerifier(15))
	codeChallenge := getCodeChallenge(verifier)
	ctx := context.Background()

	url := o.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "s256"),
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("scope", "offline_access"))

	if o.headless {
		// TODO: UI? in CLI and IDE???
		fmt.Println("Please visit:", url)
		fmt.Scanf("Enter Code: %s", responseCode)
	} else {
		browser.OpenURL(url)

		// TODO: can we use a random port to avoid ports conflicts --> check with Mike/Darrell
		srv := &http.Server{Addr: ":8080"}

		http.HandleFunc("/authorization-code/callback", func(w http.ResponseWriter, r *http.Request) {
			responseError = html.EscapeString(r.URL.Query().Get("error"))
			if len(responseError) > 0 {
				details := html.EscapeString(r.URL.Query().Get("error_description"))
				fmt.Fprintf(w, "Error during authentication! (%s)\n%s", responseError, details)
			} else {
				responseCode = html.EscapeString(r.URL.Query().Get("code"))
				responseState = html.EscapeString(r.URL.Query().Get("state"))
				fmt.Fprintf(w, "Succesfully Authenticated!")
			}

			go func() {
				time.Sleep(1000)
				srv.Shutdown(ctx)
			}()
		})

		srv.ListenAndServe()
	}

	if len(responseError) > 0 {
		return fmt.Errorf("authentication error: %s", responseError)
	}

	// check the response state before continuing
	if state != responseState {
		return fmt.Errorf("incorrect response state: %s != %s", responseState, state)
	}

	// Use the custom HTTP client when requesting a token.
	if o.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}

	token, err := o.oauthConfig.Exchange(ctx, responseCode, oauth2.SetAuthURLParam("code_verifier", string(verifier)))
	if err == nil {
		o.persistToken(token)
	}

	return err
}

func (o *oAuth2Authenticator) Authorize(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil.")
	}

	if o.token == nil {
		return fmt.Errorf("oauth token mus not be nil to authorize")
	}

	ctx := context.Background()

	// Use the custom HTTP client when requesting a token.
	if o.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}

	tokensource := o.oauthConfig.TokenSource(ctx, o.token)

	// get a valid token, refresh if necessary
	validToken, err := tokensource.Token()
	if err != nil {
		return err
	}

	if validToken != o.token {
		o.persistToken(validToken)
	}

	accessToken := validToken.AccessToken
	if len(accessToken) > 0 {
		value := fmt.Sprintf("Bearer %s", accessToken)
		request.Header.Set("Authorization", value)
	}

	return nil
}
