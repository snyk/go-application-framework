package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Output_Remove(t *testing.T) {
	tempDir := t.TempDir()
	impl := OutputDestinationImpl{}

	// case: trying to delete a non-existing file
	assert.NoFileExists(t, tempDir+"/notExistingFile")
	err := impl.Remove(tempDir + "/notExistingFile")
	assert.NoError(t, err)

	// case: trying to delete an existing file
	existingFile := tempDir + "/existingFile"
	err = os.WriteFile(existingFile, []byte("To be or not to be"), FILEPERM_666)
	assert.NoError(t, err)
	assert.FileExists(t, existingFile)
	err = impl.Remove(existingFile)
	assert.NoError(t, err)
	assert.NoFileExists(t, existingFile)
}
