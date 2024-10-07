package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	//nolint:gosec // not a token value, but a configuration key
	CONFIG_KEY_OAUTH_TOKEN  string = "INTERNAL_OAUTH_TOKEN_STORAGE"
	OAUTH_CLIENT_ID         string = "b56d4c2e-b9e1-4d27-8773-ad47eafb0956"
	CALLBACK_HOSTNAME       string = "127.0.0.1"
	CALLBACK_PATH           string = "/authorization-code/callback"
	TIMEOUT_SECONDS                = 120 * time.Second
	AUTHENTICATED_MESSAGE          = "Your account has been authenticated."
	PARAMETER_CLIENT_ID     string = "client-id"
	PARAMETER_CLIENT_SECRET string = "client-secret"
)

type GrantType int

const (
	ClientCredentialsGrant GrantType = iota
	AuthorizationCodeGrant
)

var _ Authenticator = (*oAuth2Authenticator)(nil)

var acceptedCallbackPorts = []int{8080, 18081, 28082, 38083, 48084}
var globalRefreshMutex sync.Mutex

//go:embed errorresponse.html
var errorResponsePage string

type oAuth2Authenticator struct {
	httpClient         *http.Client
	config             configuration.Configuration
	oauthConfig        *oauth2.Config
	token              *oauth2.Token
	headless           bool
	grantType          GrantType
	openBrowserFunc    func(authUrl string)
	shutdownServerFunc func(server *http.Server)
	tokenRefresherFunc func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error)
}

func OpenBrowser(authUrl string) {
	//nolint:errcheck // breaking api change needed to fix this
	browser.Stdout = os.Stderr
	_ = browser.OpenURL(authUrl)
}

func ShutdownServer(server *http.Server) {
	time.Sleep(500)
	//nolint:errcheck // breaking api change needed to fix this
	_ = server.Shutdown(context.Background())
}

func getRedirectUri(port int) string {
	callback := fmt.Sprintf("http://%s:%d%s", CALLBACK_HOSTNAME, port, CALLBACK_PATH)
	return callback
}

func getOAuthConfiguration(config configuration.Configuration) *oauth2.Config {
	appUrl := config.GetString(configuration.WEB_APP_URL)
	apiUrl := config.GetString(configuration.API_URL)
	tokenUrl := apiUrl + "/oauth2/token"
	authUrl := appUrl + "/oauth2/authorize"

	conf := &oauth2.Config{
		ClientID: OAUTH_CLIENT_ID,
		Endpoint: oauth2.Endpoint{
			TokenURL:  tokenUrl,
			AuthURL:   authUrl,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	if determineGrantType(config) == ClientCredentialsGrant {
		conf.ClientID = config.GetString(PARAMETER_CLIENT_ID)
		conf.ClientSecret = config.GetString(PARAMETER_CLIENT_SECRET)
	}

	return conf
}

func getOAuthConfigurationClientCredentials(in *oauth2.Config) *clientcredentials.Config {
	conf := &clientcredentials.Config{
		ClientID:     in.ClientID,
		ClientSecret: in.ClientSecret,
		TokenURL:     in.Endpoint.TokenURL,
	}
	return conf
}

// This method creates a code challenge as defined in https://www.rfc-editor.org/rfc/rfc7636#section-4.2
// It accepts a code verifier and returns the challenge as a URL safe string.
func getCodeChallenge(verifier []byte) string {
	shasum := sha256.Sum256(verifier)
	return base64.RawURLEncoding.EncodeToString(shasum[:])
}

// This method creates a code verifier as defined in https://www.rfc-editor.org/rfc/rfc7636#section-4.1
// It accepts the number of bytes it shall create and returns the verifier as a byte slice of the specified length.
func createVerifier(count int) ([]byte, error) {
	/*
	  unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	   ALPHA = %x41-5A / %x61-7A
	   DIGIT = %x30-39
	*/
	lut := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
	verifier := make([]byte, count)

	for i := range verifier {
		index, err := randIndex(len(lut))
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}
		verifier[i] = lut[index]
	}

	return verifier, nil
}

// randIndex provides a secure random number in the range [0, limit).
func randIndex(limit int) (int, error) {
	if limit <= 0 {
		return -1, fmt.Errorf("invalid limit %d", limit)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return -1, fmt.Errorf("failed to read secure random bytes: %w", err)
	}
	return int(n.Int64()), nil
}

// GetOAuthToken extracts an oauth2.Token from the given configuration instance if available
func GetOAuthToken(config configuration.Configuration) (*oauth2.Token, error) {
	oauthTokenString := config.GetString(CONFIG_KEY_OAUTH_TOKEN)
	if len(oauthTokenString) > 0 {
		token := &oauth2.Token{}
		err := json.Unmarshal([]byte(oauthTokenString), token)
		if err != nil {
			return nil, err
		}
		return token, nil
	}
	//nolint:nilnil // using a sentinel error here breaks existing API contract
	return nil, nil
}

func RefreshToken(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	tokenSource := oauthConfig.TokenSource(ctx, token)
	return tokenSource.Token()
}

func refreshTokenClientCredentials(ctx context.Context, oauthConfig *oauth2.Config, _ *oauth2.Token) (*oauth2.Token, error) {
	conf := getOAuthConfigurationClientCredentials(oauthConfig)
	tokenSource := conf.TokenSource(ctx)
	return tokenSource.Token()
}

func determineGrantType(config configuration.Configuration) GrantType {
	grantType := AuthorizationCodeGrant
	if config.IsSet(PARAMETER_CLIENT_SECRET) && config.IsSet(PARAMETER_CLIENT_ID) {
		grantType = ClientCredentialsGrant
	}
	return grantType
}

//goland:noinspection GoUnusedExportedFunction
func NewOAuth2Authenticator(config configuration.Configuration, httpClient *http.Client) Authenticator {
	return NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(httpClient))
}

func NewOAuth2AuthenticatorWithOpts(config configuration.Configuration, opts ...OAuth2AuthenticatorOption) Authenticator {
	o := &oAuth2Authenticator{}
	o.config = config
	//nolint:errcheck // breaking api change needed to fix this
	o.token, _ = GetOAuthToken(config)
	o.oauthConfig = getOAuthConfiguration(config)
	config.PersistInStorage(CONFIG_KEY_OAUTH_TOKEN)

	// set defaults
	o.httpClient = http.DefaultClient
	o.openBrowserFunc = OpenBrowser
	o.shutdownServerFunc = ShutdownServer
	o.grantType = determineGrantType(config)

	// set refresh function depending on grant type
	if o.grantType == ClientCredentialsGrant {
		o.tokenRefresherFunc = refreshTokenClientCredentials
	} else {
		o.tokenRefresherFunc = RefreshToken
	}

	// apply options
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Deprecated: use NewOAuth2AuthenticatorWithOpts instead
//
//goland:noinspection GoUnusedExportedFunction
func NewOAuth2AuthenticatorWithCustomFuncs(
	config configuration.Configuration,
	httpClient *http.Client,
	openBrowserFunc func(url string),
	shutdownServerFunc func(server *http.Server),
) Authenticator {
	return NewOAuth2AuthenticatorWithOpts(
		config,
		WithHttpClient(httpClient),
		WithOpenBrowserFunc(openBrowserFunc),
		WithShutdownServerFunc(shutdownServerFunc),
	)
}

func (o *oAuth2Authenticator) IsSupported() bool {
	tokenExistent := o.token != nil
	featureEnabled := o.config.GetBool(configuration.FF_OAUTH_AUTH_FLOW_ENABLED)
	return tokenExistent && featureEnabled
}

func (o *oAuth2Authenticator) persistToken(token *oauth2.Token) error {
	tokenstring, err := json.Marshal(token)
	if err != nil {
		return err
	}
	o.config.Set(CONFIG_KEY_OAUTH_TOKEN, string(tokenstring))
	o.token = token
	return nil
}

func (o *oAuth2Authenticator) Authenticate() error {
	var err error

	if o.grantType == ClientCredentialsGrant {
		err = o.authenticateWithClientCredentialsGrant()
	} else {
		err = o.authenticateWithAuthorizationCode()
	}

	return err
}

func (o *oAuth2Authenticator) authenticateWithClientCredentialsGrant() error {
	ctx := context.Background()
	config := getOAuthConfigurationClientCredentials(o.oauthConfig)

	// Use the custom HTTP client when requesting a token.
	if o.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}

	// get token
	token, err := config.Token(ctx)
	if err != nil {
		return err
	}

	err = o.persistToken(token)
	return err
}

func (o *oAuth2Authenticator) authenticateWithAuthorizationCode() error {
	var responseCode string
	var responseState string
	var responseError string
	verifier, err := createVerifier(128)
	if err != nil {
		return err
	}
	stateBytes, err := createVerifier(15)
	if err != nil {
		return err
	}
	state := string(stateBytes)
	codeChallenge := getCodeChallenge(verifier)
	ctx := context.Background()

	if o.headless {
		return errors.New("headless mode not supported")
	}

	mux := http.NewServeMux()

	//nolint:gosec // ignoring read timeouts here as we're client to ourselves
	srv := &http.Server{
		Handler: mux,
	}
	mux.HandleFunc(CALLBACK_PATH, func(w http.ResponseWriter, r *http.Request) {
		responseError = html.EscapeString(r.URL.Query().Get("error"))
		if len(responseError) > 0 {
			details := html.EscapeString(r.URL.Query().Get("error_description"))

			tmpl := template.New("")
			tmpl, tmplError := tmpl.Parse(errorResponsePage)
			if tmplError != nil {
				return
			}

			data := struct {
				Reason      string
				Description string
			}{
				Reason:      responseError,
				Description: details,
			}

			tmplError = tmpl.Execute(w, data)
			if tmplError != nil {
				return
			}
		} else {
			appUrl := o.config.GetString(configuration.WEB_APP_URL)
			responseCode = html.EscapeString(r.URL.Query().Get("code"))
			responseState = html.EscapeString(r.URL.Query().Get("state"))
			w.Header().Add("Location", appUrl+"/authenticated?type=oauth")
			w.WriteHeader(http.StatusMovedPermanently)
		}

		go o.shutdownServerFunc(srv)
	})

	// iterate over different known ports if one fails
	for _, port := range acceptedCallbackPorts {
		srv.Addr = fmt.Sprintf("%s:%d", CALLBACK_HOSTNAME, port)
		listener, listenErr := net.Listen("tcp", srv.Addr)
		if listenErr != nil { // skip port if it can't be listened to
			continue
		}

		// fill redirect url now that the port is known
		o.oauthConfig.RedirectURL = getRedirectUri(port)

		url := o.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("response_type", "code"),
			oauth2.SetAuthURLParam("scope", "offline_access"),
			oauth2.SetAuthURLParam("version", "2021-08-11~experimental"))

		// launch browser
		go o.openBrowserFunc(url)

		timedOut := false
		timer := time.AfterFunc(TIMEOUT_SECONDS, func() {
			timedOut = true
			o.shutdownServerFunc(srv)
		})
		listenErr = srv.Serve(listener)
		if errors.Is(listenErr, http.ErrServerClosed) { // if the server was shutdown normally, there is no need to iterate further
			if timedOut {
				return errors.New("authentication failed (timeout)")
			}
			timer.Stop()
			break
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
	if err != nil {
		return err
	}

	err = o.persistToken(token)
	return err
}

func (o *oAuth2Authenticator) AddAuthenticationHeader(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil")
	}
	if o.token == nil {
		return fmt.Errorf("oauth token must not be nil to authorize")
	}

	ctx := request.Context()

	if o.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}

	// Also ensure this in-process across goroutines.
	globalRefreshMutex.Lock()
	defer globalRefreshMutex.Unlock()

	// if the current token is invalid
	if !o.token.Valid() {
		// Ensure oauth token refresh is atomic and does not operate on a stale
		// token across concurrent processes.
		cleanup, err := o.syncTokenRefresh(ctx)
		defer cleanup()
		if err != nil {
			return err
		}

		// check if the token in the config is invalid as well
		token, err := GetOAuthToken(o.config)
		if err != nil {
			return err
		}

		if !token.Valid() {
			// use TokenSource to refresh the token
			validToken, err := o.tokenRefresherFunc(ctx, o.oauthConfig, o.token)
			if err != nil {
				return err
			}

			if validToken != o.token {
				if err := o.persistToken(validToken); err != nil {
					return err
				}
			}
		} else {
			o.token = token
		}
	}

	accessToken := o.token.AccessToken
	if len(accessToken) > 0 {
		value := fmt.Sprint("Bearer ", accessToken)
		request.Header.Set("Authorization", value)
		request.Header.Set("Session-Token", value)
	}

	return nil
}

const syncTokenRefreshRetryDelay = time.Millisecond * 100

// syncTokenRefresh ensures that an oauth token refresh and configuration file
// update is atomic when there are multiple concurrent processes which might
// attempt to refresh.
//
// This function also ensures that the token is up to date before refreshing.
//
// The returned cleanup function must be called, even if an error occurred.
func (o *oAuth2Authenticator) syncTokenRefresh(ctx context.Context) (func(), error) {
	cleanup := func() {}
	if storage := o.config.GetStorage(); storage != nil {
		// Lock configuration storage and refresh, to avoid oAuth2Authenticator
		// racing with itself on concurrently rotating client & refresh tokens.
		err := storage.Lock(ctx, syncTokenRefreshRetryDelay)
		if err != nil {
			return cleanup, err
		}
		cleanup = func() {
			_ = storage.Unlock() //nolint:errcheck // unlock errors are ignored, pending future GAF observability improvements
		}

		// Even if we obtained the lock, it's also possible that our
		// configuration has gone stale since originally read, by another
		// process refreshing before the above lock was reached.
		//
		// To avoid this, unconditionally refresh the configuation from its
		// storage and re-parse the oauth token stored within.
		if err = storage.Refresh(o.config, CONFIG_KEY_OAUTH_TOKEN); err != nil {
			return cleanup, err
		}
		o.token, err = GetOAuthToken(o.config)
		if err != nil {
			return cleanup, err
		}
		if o.token == nil {
			return cleanup, fmt.Errorf("oauth token must not be nil to authorize")
		}
	}

	return cleanup, nil
}
