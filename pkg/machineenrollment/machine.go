package machineenrollment

import (
	"context"
	"net/http"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// EnrollMachineOption configures an EnrollMachine call.
type EnrollMachineOption func(*enrollMachineOptions)

type enrollMachineOptions struct {
	httpClient *http.Client
	joinKey    string
	machineID  string
}

// WithHttpClient sets the HTTP client used for the enrollment request. It must not add
// authentication; enrolling is how the machine gets its credential. If unset, http.DefaultClient is
// used.
func WithHttpClient(httpClient *http.Client) EnrollMachineOption {
	return func(o *enrollMachineOptions) { o.httpClient = httpClient }
}

// WithJoinKey enrolls with the single-use join key an admin issued for this machine, identifying it
// as machineID.
func WithJoinKey(joinKey, machineID string) EnrollMachineOption {
	return func(o *enrollMachineOptions) {
		o.joinKey = joinKey
		o.machineID = machineID
	}
}

// EnrollMachine enrolls this device as a machine principal, using the join key supplied via
// WithJoinKey. It generates a new machine client key, exchanges the join key for an OAuth client
// bound to that key, writes the key to disk, and persists the enrolled machine's client id, key
// file path, and machine id into config so the caller doesn't have to wire that up itself.
func EnrollMachine(ctx context.Context, config configuration.Configuration, opts ...EnrollMachineOption) (Enrollment, error) {
	o := enrollMachineOptions{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&o)
	}

	keyFile := config.GetString(CONFIG_KEY_CLIENT_KEY_FILE)
	if keyFile == "" {
		var err error
		if keyFile, err = DefaultKeyFile(); err != nil {
			return Enrollment{}, err
		}
	}

	apiURL := config.GetString(configuration.API_URL)
	e, err := EnrollWithJoinToken(ctx, o.httpClient, apiURL, o.joinKey, o.machineID, time.Now())
	if err != nil {
		return Enrollment{}, err
	}

	if err = WriteKeyFile(keyFile, e.Key); err != nil {
		return Enrollment{}, err
	}

	for key, value := range map[string]string{
		CONFIG_KEY_CLIENT_ID:       e.ClientID,
		CONFIG_KEY_CLIENT_KEY_FILE: keyFile,
		CONFIG_KEY_MACHINE_ID:      e.MachineID,
	} {
		config.PersistInStorage(key)
		config.Set(key, value)
	}

	return e, nil
}
