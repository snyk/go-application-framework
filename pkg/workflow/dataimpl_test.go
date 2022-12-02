package workflow

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewDataFromInput(t *testing.T) {

	expectedContentType := "application/json"
	expectedContentType2 := "application/binary"
	expectedContentLocation := "/folder/of/source/file.json"

	input := NewData(NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata"), expectedContentType, []byte{})
	input.SetContentLocation(expectedContentLocation)

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

	fmt.Println(input)
	fmt.Println(output)

}
