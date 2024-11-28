package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// oauthApiUrl returns the API URL specified by the audience claim in a JWT
// token established by a prior OAuth authentication flow.
//
// Returns an empty string if an OAuth token is not available, cannot be parsed,
// or lacks such an audience claim, along with an error that may have occurred
// in the attempt to parse it.
func GetApiUrlFromOauthToken(config configuration.Configuration) (string, error) {
	oauthTokenString, ok := config.Get(auth.CONFIG_KEY_OAUTH_TOKEN).(string)
	if !ok || oauthTokenString == "" {
		return "", nil
	}
	var token oauth2.Token
	if err := json.Unmarshal([]byte(oauthTokenString), &token); err != nil {
		return "", err
	}

	return readAudience(&token)
}

// readAudience returns the first audience claim from an OAuth2 access token, or
// an error which prevented its parsing.
//
// If the claim is not present, an empty string is returned.
//
// This function was derived from https://pkg.go.dev/golang.org/x/oauth2/jws#Decode,
// which is licensed as follows:
//
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
func readAudience(token *oauth2.Token) (string, error) {
	// decode returned id token to get expiry
	s := strings.Split(token.AccessToken, ".")
	if len(s) < 2 {
		// TODO(jbd): Provide more context about the error.
		return "", errors.New("jws: invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return "", err
	}
	c := struct {
		// NOTE: The original jws package models audience with a string, not a
		// []string. This fails to parse Snyk JWTs.
		Aud []string `json:"aud"`
	}{}
	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(&c)
	if err != nil {
		return "", err
	}
	if len(c.Aud) > 0 {
		return c.Aud[0], nil
	}
	return "", nil
}
