package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var instanceList = []string{
	"snyk.io",
	"fedramp-alpha.snykgov",
	"au.snyk.io",
	"dev.snyk.io",
}

func Test_GetCanonicalApiUrlFromString(t *testing.T) {
	for _, instance := range instanceList {
		inputList := []string{
			"https://" + instance + ".io/api/v1",
			"https://" + instance + ".io/api",
			"https://app." + instance + ".io/api",
			"https://app." + instance + ".io/api/v1",
			"https://api." + instance + ".io/api/v1",
			"https://api." + instance + ".io/v1",
			"https://api." + instance + ".io",
			"https://api." + instance + ".io?something=here",
		}

		expected := "https://api." + instance + ".io"

		for _, input := range inputList {
			actual, err := GetCanonicalApiUrlFromString(input)
			t.Log(input, actual)
			assert.Nil(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func Test_GetCanonicalApiUrlFromString_Edgecases(t *testing.T) {
	inputList := []string{
		"https://127.0.0.1/api/v1",
		"https://127.0.0.1:9000/api/v1",
		"https://localhost:9000/api/v1",
		"https://localhost/api",
		"http://alpha:omega@localhost:9000",
		"http://stella:8000",
		"http://192.168.2.1/v1",
		"http://192.168.2.1:8080/v1",
		"http://[2001:db8::]/v1",
		"http://[2001:db8::]:8080/v1",
	}

	expectedList := []string{
		"https://127.0.0.1/api",
		"https://127.0.0.1:9000/api",
		"https://localhost:9000/api",
		"https://localhost/api",
		"http://alpha:omega@localhost:9000",
		"http://stella:8000",
		"http://192.168.2.1",
		"http://192.168.2.1:8080",
		"http://[2001:db8::]",
		"http://[2001:db8::]:8080",
	}

	for i, input := range inputList {
		expected := expectedList[i]
		actual, err := GetCanonicalApiUrlFromString(input)
		t.Log(input, actual)
		assert.Nil(t, err)
		assert.Equal(t, expected, actual)
	}
}

func Test_GetCanonicalApiUrlFromString_Fail(t *testing.T) {
	actual, err := GetCanonicalApiUrlFromString(":not/a/url")
	assert.NotNil(t, err)
	assert.Equal(t, "", actual)
}

func Test_DeriveAppUrl(t *testing.T) {
	for _, instance := range instanceList {
		expected := "https://app." + instance
		actual, err := DeriveAppUrl("https://api." + instance)
		assert.Nil(t, err)
		assert.Equal(t, expected, actual)
	}
}

func Test_isImmutableHost(t *testing.T) {
	hostlistLocalhost := []string{"localhost", "localhost:3123", "127.0.0.1", "127.0.0.1:437", "[::1]:3212"}
	hostlistNonLocalhost := []string{"snyk.io"}

	for _, host := range hostlistLocalhost {
		assert.True(t, isImmutableHost(host))
	}

	for _, host := range hostlistNonLocalhost {
		assert.False(t, isImmutableHost(host), host)
	}
}

func Test_IsKnownHostName(t *testing.T) {
	testCases := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"localhost:8080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:9000", true},
		{"stella", true},
		{"stella:8000", true},
		{"http://localhost", true},
		{"http://localhost:8080", true},
		{"https://127.0.0.1:9000", true},
		{"http://stella:8000", true},
		{"192.168.1.1", false},
		{"example.com", false},
		{"http://example.com", false},
	}

	for _, tc := range testCases {
		actual := IsKnownHostName(tc.host)
		assert.Equal(t, tc.expected, actual, "IsKnownHostName(%q) = %v, want %v", tc.host, actual, tc.expected)
	}
}
