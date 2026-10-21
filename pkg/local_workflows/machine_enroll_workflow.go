package localworkflows

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
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

	_, err := engine.Register(WORKFLOWID_MACHINE_ENROLL, workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(flags)), machineEnrollEntryPoint)
	return err
}

// machineEnrollEntryPoint enrolls this machine and stores its credential. It returns no data, as
// the credential is a secret.
func machineEnrollEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	if config.GetStorage() == nil {
		return nil, errors.New("enrolling is refused because the credential cannot be stored: the configuration has no storage")
	}
	deviceToken := config.GetString(flagDeviceToken)
	fleetKeyFile := config.GetString(flagFleetKeyFile)
	if (deviceToken == "") == (fleetKeyFile == "") {
		return nil, fmt.Errorf("enrolling needs exactly one of --%s or --%s", flagDeviceToken, flagFleetKeyFile)
	}

	httpClient := invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient()
	apiURL := config.GetString(configuration.API_URL)

	var enrollment machineenrollment.Enrollment
	var err error
	if deviceToken != "" {
		enrollment, err = machineenrollment.EnrollWithDeviceToken(invocationCtx.Context(), httpClient, apiURL, deviceToken, time.Now())
	} else {
		enrollment, err = enrollWithFleetKeyFile(invocationCtx.Context(), invocationCtx.GetRuntimeInfo(), httpClient, apiURL, fleetKeyFile)
	}
	if err != nil {
		return nil, err
	}

	logReplacedCredential(invocationCtx, config)
	credential := machinecredential.Credential{ClientID: enrollment.ClientID, Key: enrollment.Key}
	if err = storeEnrollment(invocationCtx.Context(), storeTimeout, config, credential, deviceToken != ""); err != nil {
		return nil, err
	}
	// Workflows run on a clone, so the engine's own configuration would not see the credential
	// until the next start.
	if engineConfig := invocationCtx.GetEngine().GetConfiguration(); engineConfig != config {
		if err = machinecredential.Publish(engineConfig, credential); err != nil {
			return nil, err
		}
	}
	return nil, nil
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

// logReplacedCredential never blocks enrolling: a stored credential that can't be read is replaced too.
func logReplacedCredential(invocationCtx workflow.InvocationContext, config configuration.Configuration) {
	logger := invocationCtx.GetEnhancedLogger()
	previous, err := machinecredential.Load(config)
	switch {
	case err == nil:
		logger.Warn().Msgf("replacing the credential of client %s", previous.ClientID)
	case !errors.Is(err, machinecredential.ErrNotEnrolled):
		logger.Warn().Err(err).Msg("replacing a stored machine credential that could not be read")
	}
}

func enrollWithFleetKeyFile(ctx context.Context, runtimeInfo runtimeinfo.RuntimeInfo, httpClient *http.Client, apiURL, fleetKeyFile string) (machineenrollment.Enrollment, error) {
	if runtimeInfo == nil {
		return machineenrollment.Enrollment{}, errors.New("failed finding the identifiers of this machine: the application provides no runtime information")
	}
	machine, err := runtimeInfo.GetMachineID()
	// A usable machine can come with an error; see runtimeinfo.RuntimeInfo.
	if err != nil && (machine.SerialNumber == "" || errors.Is(err, runtimeinfo.ErrNoMachineID)) {
		return machineenrollment.Enrollment{}, fmt.Errorf("failed finding the identifiers of this machine: %w", err)
	}
	if machine.SerialNumber == "" {
		return machineenrollment.Enrollment{}, errors.New("failed finding the identifiers of this machine: no serial number is known")
	}
	fleetKey, err := machineenrollment.ReadFleetKeyFile(fleetKeyFile)
	if err != nil {
		return machineenrollment.Enrollment{}, err
	}
	identifiers := []machineenrollment.Identifier{{Type: machineenrollment.IdentifierTypeSerialNumber, Value: machine.SerialNumber}}
	return machineenrollment.EnrollWithFleetKey(ctx, httpClient, apiURL, fleetKey, identifiers, time.Now())
}
