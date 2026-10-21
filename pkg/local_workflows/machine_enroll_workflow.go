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
	err = machinecredential.Save(invocationCtx.Context(), config, machinecredential.Credential{ClientID: enrollment.ClientID, Key: enrollment.Key})
	if err != nil {
		return nil, fmt.Errorf("enrolled as client %s but the credential could not be stored; the single-use device token is spent, so ask an admin to revoke the client before enrolling again: %w", enrollment.ClientID, err)
	}
	return nil, nil
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
