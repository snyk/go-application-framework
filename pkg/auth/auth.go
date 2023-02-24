package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

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

func getConfigration() *oauth2.Config {

	// TODO: get config from outside
	conf := &oauth2.Config{
		ClientID: "0oa37b7oa3zOoDWCe4h7",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://snyk-fedramp-alpha.okta.com/oauth2/default/v1/token",
			AuthURL:  "https://app.fedramp-alpha.snykgov.io/oauth/authorize",
		},
		RedirectURL: "http://localhost:8080/authorization-code/callback",
	}
	return conf
}

func Authenticate(httpClient *http.Client, headless bool) (token *oauth2.Token, err error) {
	var responseCode string
	var responseState string
	var responseError string
	verifier := createVerifier(128)
	state := string(createVerifier(15))
	codeChallenge := getCodeChallenge(verifier)
	ctx := context.Background()
	conf := getConfigration()

	url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "s256"),
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("scope", "offline_access"))

	if headless {
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
		return nil, fmt.Errorf("authentication error: %s", responseError)
	}

	// check the response state before continuing
	if state != responseState {
		return nil, fmt.Errorf("incorrect response state: %s != %s", responseState, state)
	}

	// Use the custom HTTP client when requesting a token.
	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	token, err = conf.Exchange(ctx, responseCode, oauth2.SetAuthURLParam("code_verifier", string(verifier)))
	return token, err
}

func Refresh(httpClient *http.Client, token *oauth2.Token) (newToken *oauth2.Token, err error) {
	if token.Valid() {
		return token, nil
	}

	ctx := context.Background()
	conf := getConfigration()

	tokenSource := conf.TokenSource(ctx, token)
	newToken, err = tokenSource.Token()

	return newToken, err
}
