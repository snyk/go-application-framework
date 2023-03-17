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

func Test_GetCanonicalApiUrl(t *testing.T) {

	for _, instance := range instanceList {

		inputList := []string{
			"https://" + instance + ".io/api/v1",
			"https://" + instance + ".io/api",
			"https://app." + instance + ".io/api",
			"https://app." + instance + ".io/api/v1",
			"https://api." + instance + ".io/v1",
			"https://api." + instance + ".io",
			"https://api." + instance + ".io?something=here",
		}

		expected := "https://api." + instance + ".io"

		for _, input := range inputList {
			actual, err := GetCanonicalApiUrl(input)
			t.Log(input, actual)
			assert.Nil(t, err)
			assert.Equal(t, expected, actual)
		}
	}

}

func Test_GetCanonicalApiUrl_Edgecases(t *testing.T) {
	inputList := []string{
		"https://localhost:9000/api/v1",
		"http://alpha:omega@localhost:9000",
	}

	expectedList := []string{
		"https://localhost:9000/api",
		"http://alpha:omega@localhost:9000",
	}

	for i, input := range inputList {
		expected := expectedList[i]
		actual, err := GetCanonicalApiUrl(input)
		t.Log(input, actual)
		assert.Nil(t, err)
		assert.Equal(t, expected, actual)
	}
}

func Test_GetCanonicalApiUrl_Fail(t *testing.T) {
	actual, err := GetCanonicalApiUrl(":not/a/url")
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
