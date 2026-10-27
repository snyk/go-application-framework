package configuration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const key = "someKey"
const expectedValue = "someValue"

func Test_JsonStorage_Set_NoConfigFile(t *testing.T) {
	// Arrange
	t.Parallel()
	testCases := []struct {
		setup           string
		customSetupFunc func(t *testing.T) string
	}{
		{
			setup: "File does not exist",
			customSetupFunc: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "test.json")
			},
		},
		{
			setup: "Leading folders to the file do not exist",
			customSetupFunc: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "nonexistent", "test.json")
			},
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.setup+" - config file is created", func(t *testing.T) {
			t.Parallel()
			configFile := testCase.customSetupFunc(t)
			storage := configuration.NewJsonStorage(configFile)

			// Act
			err := storage.Set(key, expectedValue)

			// Assert
			assert.Nil(t, err)
			storedConfig := readStoredConfigFile(t, configFile)
			assertConfigContainsKey(t, storedConfig, key, expectedValue)
		})
	}
}

func Test_JsonStorage_Set_ConfigFileHasValues(t *testing.T) { //nolint:tparallel // subtests are not mutually exclusive
	// Arrange
	t.Parallel()
	const preExistingKey = "someOtherKey"
	const preExistingValue = "someOtherValue"

	preExistingConfig := map[string]string{
		preExistingKey: preExistingValue,
	}

	unknownJson, err := json.Marshal(preExistingConfig)
	assert.NoError(t, err)
	configFile := filepath.Join(t.TempDir(), "test.json")
	err = os.WriteFile(configFile, unknownJson, 0666)
	assert.NoError(t, err)
	storage := configuration.NewJsonStorage(configFile)

	// Act
	err = storage.Set(key, expectedValue)
	assert.NoError(t, err)

	// Assert
	storedConfig := readStoredConfigFile(t, configFile)
	t.Run("File contains key", func(t *testing.T) {
		assertConfigContainsKey(t, storedConfig, key, expectedValue)
	})
	t.Run("Pre-stored values are not deleted", func(t *testing.T) {
		assertConfigContainsKey(t, storedConfig, preExistingKey, preExistingValue)
	})
	assertSetCallDoesNotDeleteOtherValues(t, storage, configFile, expectedValue, key)
	t.Run("Overwrites existing value", func(t *testing.T) {
		const newValue = "new value"
		assert.Contains(t, storedConfig, key)
		err = storage.Set(key, newValue)
		assert.NoError(t, err)
		storedConfig = readStoredConfigFile(t, configFile)
		assert.NoError(t, err)
		assert.Equal(t, newValue, storedConfig[key])
	})
}

func Test_JsonStorage_Set_BrokenConfigFile(t *testing.T) {
	// Arrange
	t.Parallel()
	brokenJson := []byte("this }}is not j[]son")
	storage := storageWithTempConfigFile(t, brokenJson)

	// Act
	err := storage.Set(key, expectedValue)

	// Assert
	t.Run("Returns an error", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, err)
	})
}

func Test_JsonStorage_Set_InvalidValue(t *testing.T) {
	// Arrange
	t.Parallel()
	storage := storageWithTempConfigFile(t, []byte("{}"))
	invalidValue := make(chan int) // invalid because channels are not JSON serializable

	// Act
	err := storage.Set(key, invalidValue)

	// Assert
	t.Run("Returns an error", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, err)
	})
}

func Test_JsonStorage_Set_EmptyFile_SetsValidEmptyJson(t *testing.T) {
	// Arrange
	t.Parallel()
	configFile := filepath.Join(t.TempDir(), "test.json")
	err := os.WriteFile(configFile, []byte(""), 0666)
	assert.NoError(t, err)
	storage := configuration.NewJsonStorage(configFile)

	// Act
	err = storage.Set(key, expectedValue)

	// Assert
	assert.NoError(t, err)
	storedConfig := readStoredConfigFile(t, configFile)
	assertConfigContainsKey(t, storedConfig, key, expectedValue)
}

func Test_JsonStorage_Set_FileHoldingNull_SetsTheKey(t *testing.T) {
	t.Parallel()
	configFile := filepath.Join(t.TempDir(), "test.json")
	assert.NoError(t, os.WriteFile(configFile, []byte("null"), 0666))
	storage := configuration.NewJsonStorage(configFile)

	err := storage.Set(key, expectedValue)

	assert.NoError(t, err)
	assertConfigContainsKey(t, readStoredConfigFile(t, configFile), key, expectedValue)
}

func storageWithTempConfigFile(t *testing.T, jsonBytes []byte) *configuration.JsonStorage {
	t.Helper()
	configFile := filepath.Join(t.TempDir(), "test.json")
	err := os.WriteFile(configFile, jsonBytes, 0666)
	assert.Nil(t, err)

	return configuration.NewJsonStorage(configFile)
}

func readStoredConfigFile(t *testing.T, configFile string) map[string]any {
	t.Helper()

	storedConfig := make(map[string]any)
	fileBytes, err := os.ReadFile(configFile)
	assert.Nil(t, err)
	err = json.Unmarshal(fileBytes, &storedConfig)
	assert.Nil(t, err)

	return storedConfig
}

func assertSetCallDoesNotDeleteOtherValues(
	t *testing.T,
	storage *configuration.JsonStorage,
	configFile string,
	preExistingValue string,
	preExistingValueKey string,
) bool {
	t.Helper()
	return t.Run("A second call to Set does not delete the first value", func(t *testing.T) {
		storedConfig := readStoredConfigFile(t, configFile)
		assert.Equal(t, preExistingValue, storedConfig[preExistingValueKey])

		err := storage.Set("SomeWildKey", "SomeWildValue")

		assert.Nil(t, err)
		storedConfig = readStoredConfigFile(t, configFile)
		assert.Equal(t, preExistingValue, storedConfig[preExistingValueKey])
	})
}

func assertConfigContainsKey(
	t *testing.T,
	storedConfig map[string]any,
	expectedValueKey string,
	expectedValue string,
) {
	t.Helper()
	assert.Equal(t, expectedValue, storedConfig[expectedValueKey])
}

func Test_JsonStorage_Set_LeavesOnlyTheConfigFileBehind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.json")
	assert.NoError(t, os.WriteFile(configFile, []byte(`{"existing":"value"}`), 0600))

	assert.NoError(t, configuration.NewJsonStorage(configFile).Set(key, expectedValue))

	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
	assertConfigContainsKey(t, readStoredConfigFile(t, configFile), key, expectedValue)
}

func Test_JsonStorage_Set_WritesThroughASymlinkedConfigFile(t *testing.T) {
	t.Parallel()
	targetDir := t.TempDir()
	linkDir := t.TempDir()
	target := filepath.Join(targetDir, "snyk.json")
	link := filepath.Join(linkDir, "config.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"existing":"value"}`), 0600))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	require.NoError(t, configuration.NewJsonStorage(link).Set(key, expectedValue))

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the symlink is kept")
	stored := readStoredConfigFile(t, target)
	assert.Equal(t, expectedValue, stored[key])
	assert.Equal(t, "value", stored["existing"])
	for _, dir := range []string{targetDir, linkDir} {
		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		assert.Len(t, entries, 1, "no temporary file is left in %s", dir)
	}
}

func Test_JsonStorage_Set_CreatesTheTargetOfADanglingSymlink(t *testing.T) {
	t.Parallel()
	targetDir := t.TempDir()
	linkDir := t.TempDir()
	target := filepath.Join(targetDir, "snyk.json")
	link := filepath.Join(linkDir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	require.NoError(t, configuration.NewJsonStorage(link).Set(key, expectedValue))

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the symlink is kept")
	assert.Equal(t, expectedValue, readStoredConfigFile(t, target)[key])
	for _, dir := range []string{targetDir, linkDir} {
		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		assert.Len(t, entries, 1, "no temporary file is left in %s", dir)
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
}

func assertSymlink(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "%s is kept as a symlink", path)
}

func Test_JsonStorage_Set_FollowsAChainOfDanglingSymlinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "c.json")
	symlinkOrSkip(t, c, b)
	symlinkOrSkip(t, b, a)

	require.NoError(t, configuration.NewJsonStorage(a).Set(key, expectedValue))

	assertSymlink(t, a)
	assertSymlink(t, b)
	assert.Equal(t, expectedValue, readStoredConfigFile(t, c)[key])
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 3, "no temporary file is left behind")
}

func Test_JsonStorage_Set_RefusesASymlinkLoopWhenReadingIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	symlinkOrSkip(t, b, a)
	symlinkOrSkip(t, a, b)

	err := configuration.NewJsonStorage(a).Set(key, expectedValue)

	require.Error(t, err, "reading the current contents refuses the loop before anything is written")
	assertSymlink(t, a)
	assertSymlink(t, b)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "nothing is written and no temporary file is left behind")
}

func Test_JsonStorage_Set_FollowsARelativeSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "real"), 0o755))
	link := filepath.Join(dir, "config.json")
	symlinkOrSkip(t, filepath.Join("real", "snyk.json"), link)

	require.NoError(t, configuration.NewJsonStorage(link).Set(key, expectedValue))

	assertSymlink(t, link)
	assert.Equal(t, expectedValue, readStoredConfigFile(t, filepath.Join(dir, "real", "snyk.json"))[key])
}

func Test_JsonStorage_Set_ResolvesARelativeTargetAgainstTheLinksPhysicalDirectory(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for _, dir := range []string{"data/cfg", "data/shared", "home"} {
		require.NoError(t, os.MkdirAll(filepath.Join(base, dir), 0o755))
	}
	symlinkOrSkip(t, filepath.Join(base, "data", "cfg"), filepath.Join(base, "home", "configstore"))
	link := filepath.Join(base, "home", "configstore", "snyk.json")
	symlinkOrSkip(t, filepath.Join("..", "shared", "snyk.json"), link)

	require.NoError(t, configuration.NewJsonStorage(link).Set(key, expectedValue))

	assertSymlink(t, link)
	assert.Equal(t, expectedValue, readStoredConfigFile(t, link)[key], "the value is where a read of the link finds it")
	assert.FileExists(t, filepath.Join(base, "data", "shared", "snyk.json"))
	assert.NoDirExists(t, filepath.Join(base, "home", "shared"))
}

func Test_JsonStorage_Set_ResolvesASymlinkedDirectoryInsideTheTargetBeforeDotDot(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for _, dir := range []string{"other/inner", "dir"} {
		require.NoError(t, os.MkdirAll(filepath.Join(base, dir), 0o755))
	}
	symlinkOrSkip(t, filepath.Join(base, "other", "inner"), filepath.Join(base, "dir", "sub"))
	link := filepath.Join(base, "dir", "config.json")
	// Not filepath.Join: it would clean the ".." away before the link is even created.
	symlinkOrSkip(t, "sub"+string(filepath.Separator)+".."+string(filepath.Separator)+"f.json", link)

	require.NoError(t, configuration.NewJsonStorage(link).Set(key, expectedValue))

	assertSymlink(t, link)
	assert.Equal(t, expectedValue, readStoredConfigFile(t, link)[key], "the value is where a read of the link finds it")
	assert.FileExists(t, filepath.Join(base, "other", "f.json"))
	assert.NoFileExists(t, filepath.Join(base, "dir", "f.json"))
}
