package config_workflow

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	// argsAlias reads the positional arguments without the default of INPUT_DIRECTORY, which is the working directory.
	argsAlias      = "internal_config_args"
	lockTimeout    = 30 * time.Second
	lockRetryDelay = 100 * time.Millisecond
)

var WORKFLOWID_CONFIG workflow.Identifier = workflow.NewWorkflowIdentifier("config")

// configWorkflowEntryPoint lists the stored keys and their values, with the values of INTERNAL_ keys masked. Any
// positional argument is an unknown subcommand.
func configWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	if args := config.GetStringSlice(argsAlias); len(args) > 0 {
		return nil, cli.NewCommandArgsError(fmt.Sprintf("Unknown config command %q", args[0]))
	}
	values, err := readConfigFile(config)
	if err != nil {
		return nil, err
	}

	lines := make([]string, 0, len(values))
	for _, key := range slices.Sorted(maps.Keys(values)) {
		value := displayValue(values[key])
		if strings.HasPrefix(strings.ToUpper(key), "INTERNAL_") {
			value = logging.SANITIZE_REPLACEMENT_STRING
		}
		lines = append(lines, key+": "+value)
	}
	// trimming the whole listing drops the trailing space of a last empty value
	return textOutput(WORKFLOWID_CONFIG, strings.TrimSpace(strings.Join(lines, "\n"))), nil
}

// fileStorage returns a storage that reads and writes the configuration's file as stored, with keys as typed and
// number text kept, as the legacy config command does. The configuration itself cannot do that. Its Get resolves a
// value from flags, environment variables, defaults and alternative keys, not from the file alone. Its storage
// renames keys on write, such as snyk_token to api, and for the default file also rounds numbers and fails on a blank
// file. So only the path comes from the configuration: the selected profile's file, or the default file. Both files
// then behave alike.
//
// The legacy CLI keeps the default file in $XDG_CONFIG_HOME/configstore/snyk.json when XDG_CONFIG_HOME is set, and GAF
// ignores the variable. The default file follows legacy, so users who set it keep seeing their stored values. A
// profile's file never moves, because legacy has no profiles.
func fileStorage(config configuration.Configuration) (*configuration.JsonStorage, error) {
	storage, ok := config.GetStorage().(*configuration.JsonStorage)
	if !ok {
		return nil, cli.NewGeneralCLIFailureError("The configuration is not stored in a file.")
	}
	path := storage.Path()
	// the default file is recognized by its path, because the configuration of a profile does not name the profile
	if xdg := config.GetString("XDG_CONFIG_HOME"); xdg != "" && filepath.Clean(path) == filepath.Join(configuration.DefaultStorageDir(), "snyk.json") {
		path = filepath.Join(xdg, "configstore", "snyk.json")
	}
	return configuration.NewJsonStorage(path, configuration.WithExactNumbers(), configuration.WithBlankFileAsEmpty()), nil
}

func readConfigFile(config configuration.Configuration) (map[string]any, error) {
	storage, err := fileStorage(config)
	if err != nil {
		return nil, err
	}
	values, err := storage.ReadAll()
	return values, fileError(err)
}

// writeLocked runs write under the file lock, which a token refresh in another process takes too.
func writeLocked(ctx context.Context, config configuration.Configuration, write func(*configuration.JsonStorage) error) error {
	storage, err := fileStorage(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	if err = storage.Lock(ctx, lockRetryDelay); err != nil {
		return fileError(err)
	}
	defer func() { _ = storage.Unlock() }() //nolint:errcheck // nothing to do about a failed unlock
	return fileError(write(storage))
}

// fileError wraps a failed access to the file in a catalog error. The OS error text goes to the detail, never to
// Error().
func fileError(err error) error {
	if err == nil {
		return nil
	}
	return cli.NewGeneralCLIFailureError(err.Error(), snyk_errors.WithCause(err))
}

// displayValue formats a value as JavaScript's String() does.
func displayValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "[object Object]"
	case []any:
		items := make([]string, len(v))
		for i, item := range v {
			if item != nil {
				items[i] = displayValue(item)
			}
		}
		return strings.Join(items, ",")
	default:
		return fmt.Sprint(v)
	}
}

// textOutput returns text for the default output, which ends it with a newline. Empty text returns no data, so nothing
// is printed.
func textOutput(id workflow.Identifier, text string) []workflow.Data {
	if text == "" {
		return nil
	}
	return []workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(id, "config"), "text/plain", []byte(text))}
}
