package auth

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"golang.org/x/oauth2"
)

func Authenticate(config configuration.Configuration) {
	fmt.Println("OAuth?")

	// ctx := context.Background()

	go func() {

	}()

	conf := &oauth2.Config{
		ClientID: "",
		Endpoint: oauth2.Endpoint{
			TokenURL: "",
			AuthURL:  "",
		},
		RedirectURL: "",
	}

	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", "hello"))
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// var code string
	// if _, err := fmt.Scan(&code); err != nil {
	// 	log.Fatal(err)
	// }

	// // Use the custom HTTP client when requesting a token.
	// networkAccess := networking.NewNetworkAccess(config)
	// httpClient := networkAccess.GetHttpClient()
	// ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	// tok, err := conf.Exchange(ctx, code)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// client := conf.Client(ctx, tok)
	// _ = client
}
