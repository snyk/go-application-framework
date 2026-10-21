package machineidentity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// EnrollMachineOption configures an EnrollMachine call.
type EnrollMachineOption func(*enrollMachineOptions)

type enrollMachineOptions struct {
	httpClient      *http.Client
	deviceToken     string
	fleetKeyFile    string
	identifiersFunc machineenrollment.IdentifierSource
}

// WithHttpClient sets the HTTP client used for the enrollment request. It must not add
// authentication; enrolling is how the machine gets its credential. If unset, http.DefaultClient is
// used.
func WithHttpClient(httpClient *http.Client) EnrollMachineOption {
	return func(o *enrollMachineOptions) { o.httpClient = httpClient }
}

// WithDeviceToken enrolls with the single-use device token an admin issued for this machine.
func WithDeviceToken(deviceToken string) EnrollMachineOption {
	return func(o *enrollMachineOptions) { o.deviceToken = deviceToken }
}

// WithFleetKeyFile enrolls with the fleet key in the PEM file at path (see machineenrollment.ReadFleetKeyFile), naming
// this machine by its serial numbers, unless WithIdentifierSource says otherwise.
func WithFleetKeyFile(path string) EnrollMachineOption {
	return func(o *enrollMachineOptions) { o.fleetKeyFile = path }
}

// WithIdentifierSource sets where a fleet key enrollment gets the identifiers of this machine from.
// If unset, machineenrollment.SerialNumbers is used.
func WithIdentifierSource(source machineenrollment.IdentifierSource) EnrollMachineOption {
	return func(o *enrollMachineOptions) { o.identifiersFunc = source }
}

// EnrollMachine enrolls this device as a machine principal, using the device token supplied via
// WithDeviceToken or the fleet key supplied via WithFleetKeyFile, and exactly one of them. It
// generates a new machine client key, exchanges the device token or fleet key for an OAuth client
// bound to that key, writes the key to disk, and persists the enrolled machine's client id, key
// file path, and machine id into config so the caller doesn't have to wire that up itself.
func EnrollMachine(ctx context.Context, config configuration.Configuration, opts ...EnrollMachineOption) (machineenrollment.Enrollment, error) {
	o := enrollMachineOptions{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&o)
	}

	if (o.deviceToken == "") == (o.fleetKeyFile == "") {
		return machineenrollment.Enrollment{}, errors.New("enrolling needs either a device token or a fleet key file")
	}

	keyFile := config.GetString(CONFIG_KEY_CLIENT_KEY_FILE)
	if keyFile == "" {
		var err error
		if keyFile, err = machineenrollment.DefaultKeyFile(); err != nil {
			return machineenrollment.Enrollment{}, err
		}
	}

	apiURL := config.GetString(configuration.API_URL)
	e, err := enrollWithOptions(ctx, apiURL, o)
	if err != nil {
		return machineenrollment.Enrollment{}, err
	}

	if err = machineenrollment.WriteKeyFile(keyFile, e.Key); err != nil {
		return machineenrollment.Enrollment{}, err
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

func enrollWithOptions(ctx context.Context, apiURL string, o enrollMachineOptions) (machineenrollment.Enrollment, error) {
	if o.deviceToken != "" {
		return machineenrollment.EnrollWithDeviceToken(ctx, o.httpClient, apiURL, o.deviceToken, time.Now())
	}

	fleetKey, err := machineenrollment.ReadFleetKeyFile(o.fleetKeyFile)
	if err != nil {
		return machineenrollment.Enrollment{}, err
	}
	source := o.identifiersFunc
	if source == nil {
		source = machineenrollment.SerialNumbers
	}
	identifiers, err := source(ctx)
	if err != nil {
		return machineenrollment.Enrollment{}, fmt.Errorf("failed finding the identifiers of this machine: %w", err)
	}
	return machineenrollment.EnrollWithFleetKey(ctx, o.httpClient, apiURL, fleetKey, identifiers, time.Now())
}
