package localworkflows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	machineEnrollWorkflowName = "machine.enroll"
	flagDeviceToken           = machinecredential.CONFIG_KEY_DEVICE_TOKEN
	flagFleetKeyFile          = "fleet-key-file"
)

const storeTimeout = 30 * time.Second

var WORKFLOWID_MACHINE_ENROLL workflow.Identifier = workflow.NewWorkflowIdentifier(machineEnrollWorkflowName)

// InitMachineEnrollWorkflow initializes the machine.enroll workflow before registering it with the engine.
func InitMachineEnrollWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(machineEnrollWorkflowName, pflag.ExitOnError)
	flags.String(flagDeviceToken, "", "single-use device token issued for this machine")
	flags.String(flagFleetKeyFile, "", "path to the PEM file of a fleet key registered for this machine")
	flags.Bool(jsonFlag, false, "output the client id, enrolled machine id and key id in json format")

	_, err := engine.Register(WORKFLOWID_MACHINE_ENROLL, workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(flags)), machineEnrollEntryPoint)
	return err
}

// machineEnrollEntryPoint enrolls this machine and stores its credential; the private key never reaches the output.
func machineEnrollEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	if storage := config.GetStorage(); storage == nil || isEmptyStorage(storage) {
		return nil, errors.New("enrolling is refused because the credential cannot be stored: the configuration has no storage")
	}
	deviceToken := config.GetString(flagDeviceToken)
	fleetKeyFile := config.GetString(flagFleetKeyFile)
	if (deviceToken == "") == (fleetKeyFile == "") {
		return nil, fmt.Errorf("enrolling needs exactly one of --%s or --%s", flagDeviceToken, flagFleetKeyFile)
	}

	// The host's error handler would replace the service's error response, which carries the
	// enrollment error code, with an error catalog error.
	networkAccess := invocationCtx.GetNetworkAccess().Clone()
	networkAccess.AddErrorHandler(nil)
	httpClient := networkAccess.GetUnauthorizedHttpClient()
	apiURL := config.GetString(configuration.API_URL)
	// The device token is single-use and the client key enrolls once: a replay after the server
	// consumed them fails and orphans the client it created.
	ctx := middleware.WithoutRetry(invocationCtx.Context())

	var enrollment machineenrollment.Enrollment
	var err error
	if deviceToken != "" {
		enrollment, err = machineenrollment.EnrollWithDeviceToken(ctx, httpClient, apiURL, deviceToken, time.Now())
	} else {
		enrollment, err = enrollWithFleetKeyFile(ctx, invocationCtx.GetEnhancedLogger(), invocationCtx.GetRuntimeInfo(), httpClient, apiURL, fleetKeyFile)
	}
	if err != nil {
		return nil, err
	}

	logReplacement := replacedCredentialLogger(invocationCtx, config)
	credential := machinecredential.Credential{ClientID: enrollment.ClientID, Key: enrollment.Key}
	if err = storeEnrollment(invocationCtx.Context(), storeTimeout, config, credential, deviceToken != ""); err != nil {
		return nil, err
	}
	logReplacement()
	// Workflows run on a clone, so the engine's own configuration would not see the credential
	// until the next start.
	if engineConfig := invocationCtx.GetEngine().GetConfiguration(); engineConfig != config {
		if err = machinecredential.Publish(engineConfig, credential); err != nil {
			return nil, err
		}
	}
	return enrollmentData(enrollment, config.GetBool(jsonFlag))
}

func enrollmentData(enrollment machineenrollment.Enrollment, asJSON bool) ([]workflow.Data, error) {
	contentType := "text/plain"
	payload := fmt.Appendf(nil, "Enrolled machine %s as client %s with key %s", enrollment.MachineID, enrollment.ClientID, enrollment.KeyID)
	if asJSON {
		var err error
		contentType = "application/json"
		payload, err = json.Marshal(struct {
			ClientID  string `json:"client_id"`
			MachineID string `json:"enrolled_machine_id"`
			KeyID     string `json:"key_id"`
		}{ClientID: enrollment.ClientID, MachineID: enrollment.MachineID, KeyID: enrollment.KeyID})
		if err != nil {
			return nil, err
		}
	}
	return []workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_MACHINE_ENROLL, machineEnrollWorkflowName), contentType, payload)}, nil
}

func isEmptyStorage(storage configuration.Storage) bool {
	_, ok := storage.(*configuration.EmptyStorage)
	return ok
}

func storeEnrollment(ctx context.Context, timeout time.Duration, config configuration.Configuration, credential machinecredential.Credential, usedDeviceToken bool) error {
	// The client exists already: an interrupted invocation must not orphan it, and another process's
	// lock must not hold this one forever. WithoutCancel only helps if the host does not exit on SIGINT.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	err := machinecredential.Save(ctx, config, credential)
	if err != nil {
		return storeFailure(credential.ClientID, usedDeviceToken, err)
	}
	return nil
}

func storeFailure(clientID string, usedDeviceToken bool, cause error) error {
	if usedDeviceToken {
		return fmt.Errorf("enrolled as client %s but the credential could not be stored; the single-use device token is spent, so ask an admin to revoke the client before enrolling again: %w", clientID, cause)
	}
	return fmt.Errorf("enrolled as client %s but the credential could not be stored; the enrollment service created a client for this machine, which an admin may want to revoke: %w", clientID, cause)
}

// replacedCredentialLogger reads the stored credential now, as storing overwrites it, and returns the
// function that logs its replacement. It never blocks enrolling: a stored credential that can't be
// read is replaced too.
func replacedCredentialLogger(invocationCtx workflow.InvocationContext, config configuration.Configuration) func() {
	logger := invocationCtx.GetEnhancedLogger()
	previous, err := machinecredential.Load(config)
	switch {
	case err == nil:
		return func() { logger.Warn().Msgf("replaced the credential of client %s", previous.ClientID) }
	case !errors.Is(err, machinecredential.ErrNotEnrolled):
		return func() { logger.Warn().Err(err).Msg("replaced a stored machine credential that could not be read") }
	}
	return func() {}
}

func enrollWithFleetKeyFile(ctx context.Context, logger *zerolog.Logger, runtimeInfo runtimeinfo.RuntimeInfo, httpClient *http.Client, apiURL, fleetKeyFile string) (machineenrollment.Enrollment, error) {
	if runtimeInfo == nil {
		return machineenrollment.Enrollment{}, errors.New("failed finding the identifiers of this machine: the application provides no runtime information")
	}
	machine, err := runtimeInfo.GetMachineID()
	// Only the serial number is sent for now, for the initial rollout. Later this will either send the
	// derived machine id or the whole runtimeinfo.Machine and let the backend decide.
	// A usable machine can come with an error; see runtimeinfo.RuntimeInfo.
	if err != nil && (machine.SerialNumber == "" || errors.Is(err, runtimeinfo.ErrNoMachineID)) {
		return machineenrollment.Enrollment{}, fmt.Errorf("failed finding the identifiers of this machine: %w", err)
	}
	if machine.SerialNumber == "" {
		return machineenrollment.Enrollment{}, errors.New("failed finding the identifiers of this machine: no serial number is known")
	}
	warnIfReadableByOthers(logger, fleetKeyFile)
	fleetKey, err := machineenrollment.ReadFleetKeyFile(fleetKeyFile)
	if err != nil {
		return machineenrollment.Enrollment{}, err
	}
	identifiers := []machineenrollment.Identifier{{Type: machineenrollment.IdentifierTypeSerialNumber, Value: machine.SerialNumber}}
	return machineenrollment.EnrollWithFleetKey(ctx, httpClient, apiURL, fleetKey, identifiers, time.Now())
}

// warnIfReadableByOthers logs when other users of this system can read the fleet key. It does not
// refuse the key: a container secret mount can't be chmod'ed, and ReadFleetKeyFile reports a file
// that can't be read at all.
func warnIfReadableByOthers(logger *zerolog.Logger, path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 == 0 {
		return
	}
	logger.Warn().Msgf("the fleet key file is readable by other users: run chmod 600 %q, or mount a container secret with defaultMode 0400", path)
}
