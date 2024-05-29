package workflow

import (
	"fmt"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

func Test_NewDataFromInput(t *testing.T) {
	expectedContentType := "application/json"
	expectedContentType2 := "application/binary"
	expectedContentLocation := "/folder/of/source/file.json"

	input := NewData(NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata"), expectedContentType, []byte{})
	input.SetContentLocation(expectedContentLocation)
	input.AddError(snyk_errors.Error{
		Title:          "Generic but helpful error message",
		Classification: "ACTIONABLE",
		Level:          "warning",
		Detail:         "Error code detail",
		Links:          []string{"https://docs.snyk.io/\n"},
	})

	output := NewDataFromInput(input, NewTypeIdentifier(NewWorkflowIdentifier("yourcommand"), "yourdata"), expectedContentType2, []byte{})

	actualContentLocation := output.GetContentLocation()
	assert.Equal(t, expectedContentLocation, actualContentLocation)

	actualContentLocation = input.GetContentLocation()
	assert.Equal(t, expectedContentLocation, actualContentLocation)

	expectedFragment := input.GetIdentifier().Fragment
	actualFragment := output.GetIdentifier().Fragment
	assert.Equal(t, expectedFragment, actualFragment)

	assert.Equal(t, expectedContentType, input.GetContentType())
	assert.Equal(t, expectedContentType2, output.GetContentType())
	assert.Equal(t, input.GetErrorList(), output.GetErrorList())

	fmt.Println(input)
	fmt.Println(output)
}
