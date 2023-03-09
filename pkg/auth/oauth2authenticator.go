package auth

import (
	"context"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/browser"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"golang.org/x/oauth2"
)

const (
	CONFIG_KEY_OAUTH_TOKEN string = "OAUTH_TOKEN"
	OAUTH_CLIENT_ID        string = "0oa37b7oa3zOoDWCe4h7"
	CALLBACK_HOSTNAME      string = "127.0.0.1"
	CALLBACK_PATH          string = "/authorization-code/callback"
)

var accepted_callback_ports = []int{8080, 18081, 28082, 38083, 48084}

type oAuth2Authenticator struct {
	httpClient         *http.Client
	config             configuration.Configuration
	oauthConfig        *oauth2.Config
	token              *oauth2.Token
	headless           bool
	openBrowserFunc    func(authUrl string)
	shutdownServerFunc func(server *http.Server)
}

func init() {
	var seed int64
	var b [8]byte
	_, err := crypto_rand.Read(b[:])
	if err != nil {
		seed = time.Now().UnixNano() // fallback to time only if necessary
	} else {
		seed = int64(binary.LittleEndian.Uint64(b[:])) // based on https://stackoverflow.com/a/54491783
	}
	rand.Seed(seed)
}

func openBrowser(authUrl string) {
	_ = browser.OpenURL(authUrl)
}

func shutdownServer(server *http.Server) {
	time.Sleep(500)
	_ = server.Shutdown(context.Background())
}

func getRedirectUri(port int) string {
	callback := fmt.Sprintf("http://%s:%d%s", CALLBACK_HOSTNAME, port, CALLBACK_PATH)
	return callback
}

func getOAuthConfiguration(config configuration.Configuration) *oauth2.Config {

	appUrl := config.GetString(configuration.WEB_APP_URL)
	tokenUrl := strings.Replace(appUrl, "app.", "id.", 1) + "/oauth2/default/v1/token"
	tokenUrl = "https://snyk-fedramp-alpha.okta.com/oauth2/default/v1/token" // TODO remove as soon as the derived tokenUrl works
	authUrl := appUrl + "/oauth/authorize"

	conf := &oauth2.Config{
		ClientID: OAUTH_CLIENT_ID,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenUrl,
			AuthURL:  authUrl,
		},
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
	verifier := make([]byte, count)

	// TODO is this good enough?
	for i := range verifier {
		index := rand.Int() % len(lut)
		verifier[i] = lut[index]
	}

	return verifier
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
	oauthConfig := getOAuthConfiguration(config)

	return &oAuth2Authenticator{
		httpClient:         httpClient,
		config:             config,
		oauthConfig:        oauthConfig,
		token:              token,
		openBrowserFunc:    openBrowser,
		shutdownServerFunc: shutdownServer,
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

	if o.headless {
		// TODO:
	} else {
		srv := &http.Server{}

		http.HandleFunc(CALLBACK_PATH, func(w http.ResponseWriter, r *http.Request) {
			responseError = html.EscapeString(r.URL.Query().Get("error"))
			if len(responseError) > 0 {
				details := html.EscapeString(r.URL.Query().Get("error_description"))
				fmt.Fprintf(w, "Error during authentication! (%s)\n%s", responseError, details)
			} else {
				responseCode = html.EscapeString(r.URL.Query().Get("code"))
				responseState = html.EscapeString(r.URL.Query().Get("state"))
				fmt.Fprintf(w, "Succesfully Authenticated!")
			}

			go o.shutdownServerFunc(srv)
		})

		// iterate over different known ports if one fails
		for _, port := range accepted_callback_ports {
			srv.Addr = fmt.Sprintf("%s:%d", CALLBACK_HOSTNAME, port)
			listener, err := net.Listen("tcp", srv.Addr)
			if err != nil { // skip port if it can't be listened to
				continue
			}

			// fill redirect url now that the port is known
			o.oauthConfig.RedirectURL = getRedirectUri(port)

			url := o.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", "s256"),
				oauth2.SetAuthURLParam("response_type", "code"),
				oauth2.SetAuthURLParam("scope", "offline_access"))

			// launch browser
			go o.openBrowserFunc(url)

			err = srv.Serve(listener)
			if err == http.ErrServerClosed { // if the server was shutdown normally, there is no need to iterate further
				break
			}
		}
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

func (o *oAuth2Authenticator) AddAuthenticationHeader(request *http.Request) error {
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
