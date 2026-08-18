package ufm

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// Test is a single test and the results it produced.
//
// Metadata holds facts about the test as a whole, such as the asset it covers. They belong
// to the test rather than to any one result, which matters when a test is reported per
// component: without a home of their own such facts have to be copied onto every result and
// then reconciled again at render time.
type Test struct {
	Metadata map[string]interface{}
	Results  []testapi.TestResult
}

// AssetLink returns the inventory link of the asset the test covers, or an empty string if
// it covers none. A test has at most one asset.
func (t Test) AssetLink() string {
	link, ok := t.Metadata[testapi.TestResultMetadataKeyAsset].(string)
	if !ok {
		return ""
	}
	return link
}

// jsonTest is the wire format of Test. Results is typed concretely so that it can be
// unmarshalled, which the testapi.TestResult interface does not allow.
type jsonTest struct {
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Results  []*jsonTestResult      `json:"results"`
}

func (j *jsonTest) toTest() Test {
	results := make([]testapi.TestResult, len(j.Results))
	for i, result := range j.Results {
		results[i] = result
	}

	return Test{Metadata: j.Metadata, Results: results}
}

// unmarshalTest reads either wire format: an object holding the test and its results, or a
// bare array of results as written before tests carried metadata of their own.
func unmarshalTest(jsonBytes []byte) (*jsonTest, error) {
	if isJSONArray(jsonBytes) {
		var results []*jsonTestResult
		if err := json.Unmarshal(jsonBytes, &results); err != nil {
			return nil, fmt.Errorf("failed to unmarshal test results: %w", err)
		}
		return &jsonTest{Results: results}, nil
	}

	var test jsonTest
	if err := json.Unmarshal(jsonBytes, &test); err != nil {
		return nil, fmt.Errorf("failed to unmarshal test: %w", err)
	}
	return &test, nil
}

// isJSONArray reports whether the first meaningful byte opens an array.
func isJSONArray(jsonBytes []byte) bool {
	for _, b := range jsonBytes {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// NewSerializableTestFromBytes deserializes a test and its results.
func NewSerializableTestFromBytes(jsonBytes []byte) (*Test, error) {
	test, err := unmarshalTest(jsonBytes)
	if err != nil {
		return nil, err
	}

	result := test.toTest()
	return &result, nil
}
