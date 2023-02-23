package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/url"
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

func Authenticate(httpClient *http.Client, headless bool) (token *oauth2.Token, err error) {
	var responseCode string
	verifier := createVerifier(128)
	codeChallenge := getCodeChallenge(verifier)
	ctx := context.Background()

	// TODO: get config from outside
	conf := &oauth2.Config{
		ClientID: "REPLACE_ME",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://snyk-fedramp-alpha.okta.com/oauth2/default/v1/token",
			AuthURL:  "https://snyk-fedramp-alpha.okta.com/oauth2/default/v1/authorize",
		},
	}

	// TOOD: there seems to be more required when running headless
	if !headless {
		conf.RedirectURL = "http://localhost:8080/authorization-code/callback"
	}

	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "s256"),
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("scope", url.QueryEscape("openid")))

	if headless {
		// TODO: UI? in CLI and IDE???
		fmt.Println("Please visit:", url)
		fmt.Scanf("Enter Code: %s", responseCode)
	} else {
		browser.OpenURL(url)

		// TODO: can we use a random port to avoid ports conflicts --> check with Mike/Darrell
		srv := &http.Server{Addr: ":8080"}

		http.HandleFunc("/authorization-code/callback", func(w http.ResponseWriter, r *http.Request) {
			responseCode = html.EscapeString(r.URL.Query().Get("code"))
			fmt.Fprintf(w, "Code, %q", responseCode)

			// TODO very rough handling, causes localhost website to not show
			srv.Shutdown(ctx)
		})

		srv.ListenAndServe()
	}

	// Use the custom HTTP client when requesting a token.
	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	// TODO the docs say "Before calling Exchange, be sure to validate FormValue("state")."
	token, err = conf.Exchange(ctx, responseCode, oauth2.SetAuthURLParam("code_verifier", string(verifier)))
	return token, err
}
