package localworkflows

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type enrollEnv struct {
	home   string
	server *enrollmenttest.Server
	engine workflow.Engine
	config configuration.Configuration
}

func newEnrollEnv(t *testing.T) *enrollEnv {
	t.Helper()
	return newEnrollEnvWithRuntimeInfo(t, true)
}

func newEnrollEnvWithRuntimeInfo(t *testing.T, withRuntimeInfo bool) *enrollEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	server := enrollmenttest.NewServer(t)
	config := openFileBackedConfig()
	config.Set(configuration.API_URL, server.URL)

	engine := workflow.NewWorkFlowEngine(config)
	if withRuntimeInfo {
		engine.SetRuntimeInfo(runtimeinfo.New())
	}
	require.NoError(t, InitMachineEnrollWorkflow(engine))
	require.NoError(t, engine.Init())
	return &enrollEnv{home: home, server: server, engine: engine, config: config}
}

func openFileBackedConfig() configuration.Configuration {
	return configuration.NewWithOpts(configuration.WithFiles("snyk"))
}

func (e *enrollEnv) enroll(flags map[string]string) error {
	invokeConfig := e.config.Clone()
	for name, value := range flags {
		invokeConfig.Set(name, value)
	}
	_, err := e.engine.InvokeWithConfig(WORKFLOWID_MACHINE_ENROLL, invokeConfig)
	return err
}

func requestToken(t *testing.T, server *enrollmenttest.Server, credential machinecredential.Credential) *http.Response {
	t.Helper()
	tokenURL := server.URL + "/oauth2/token"
	assertionType, assertion, err := machinecredential.NewSigner(credential.Key).ClientAssertion(t.Context(), credential.ClientID, tokenURL)
	require.NoError(t, err)

	res, err := server.Client().PostForm(tokenURL, url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {credential.ClientID},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			files = append(files, path)
		}
		return err
	}))
	return files
}

func Test_machineEnroll_installerEnrollsWithDeviceToken(t *testing.T) {
	env := newEnrollEnv(t)
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))

	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: deviceToken}))

	reopened := openFileBackedConfig()
	credential, err := machinecredential.Load(reopened)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, requestToken(t, env.server, credential).StatusCode, "the fake service accepts an assertion signed with the stored key")

	for _, file := range filesUnder(t, env.home) {
		assert.False(t, strings.HasSuffix(file, ".pem"), "unexpected key file %s", file)
	}
	assert.NoDirExists(t, filepath.Join(env.home, ".snyk"))
	assert.Equal(t, 1, env.server.ClientCount())
}

func (e *enrollEnv) setMachine(machine runtimeinfo.Machine) {
	e.config.Set(configuration.MACHINE_ID, machine)
}

func writeFleetKey(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "fleet.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path, key
}

func Test_machineEnroll_fleetKeyNamesTheMachineBySerialNumber(t *testing.T) {
	env := newEnrollEnv(t)
	machineID := env.server.RegisterMachine("SERIAL-42")
	fleetKeyFile, fleetKey := writeFleetKey(t)
	env.server.AllowFleetKey(&fleetKey.PublicKey, machineID)
	env.setMachine(runtimeinfo.Machine{ID: "stable-id", SerialNumber: "SERIAL-42"})

	require.NoError(t, env.enroll(map[string]string{flagFleetKeyFile: fleetKeyFile}))

	credential, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, requestToken(t, env.server, credential).StatusCode)
}

func assertNothingStored(t *testing.T, home string) {
	t.Helper()
	_, err := machinecredential.Load(openFileBackedConfig())
	assert.ErrorIs(t, err, machinecredential.ErrNotEnrolled)
	for _, file := range filesUnder(t, home) {
		content, readErr := os.ReadFile(file)
		require.NoError(t, readErr)
		assert.NotContains(t, string(content), "private_key_pem", file)
	}
}

func Test_machineEnroll_rejectedDeviceTokenLeavesTheStoredCredentialUntouched(t *testing.T) {
	env := newEnrollEnv(t)
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))
	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: deviceToken}))
	first, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)

	err = env.enroll(map[string]string{flagDeviceToken: deviceToken})

	var enrollmentErr *machineenrollment.EnrollmentError
	require.ErrorAs(t, err, &enrollmentErr, "the service rejection is reported")
	assert.Equal(t, http.StatusUnauthorized, enrollmentErr.Status)
	after, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, first.ClientID, after.ClientID)
	assert.Equal(t, http.StatusOK, requestToken(t, env.server, after).StatusCode, "the stored key is still the enrolled one")
}

func Test_machineEnroll_needsExactlyOneCredentialFlag(t *testing.T) {
	fleetKeyFile, _ := writeFleetKey(t)
	for name, flags := range map[string]map[string]string{
		"neither": {},
		"both":    {flagDeviceToken: "sdt_x", flagFleetKeyFile: fleetKeyFile},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnrollEnv(t)

			err := env.enroll(flags)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "--"+flagDeviceToken)
			assert.Contains(t, err.Error(), "--"+flagFleetKeyFile)
			assertNothingStored(t, env.home)
		})
	}
}

func Test_machineEnroll_fleetKeyWithoutKnownSerialNumberStoresNothing(t *testing.T) {
	fleetKeyFile, _ := writeFleetKey(t)
	for name, machine := range map[string]*runtimeinfo.Machine{
		"empty serial number": {ID: "stable-id"},
		"no machine id":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnrollEnv(t)
			if machine != nil {
				env.setMachine(*machine)
			}

			err := env.enroll(map[string]string{flagFleetKeyFile: fleetKeyFile})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "identifiers of this machine")
			assertNothingStored(t, env.home)
		})
	}
}

func Test_machineEnroll_fleetKeyWithoutRuntimeInfoStoresNothing(t *testing.T) {
	fleetKeyFile, _ := writeFleetKey(t)
	env := newEnrollEnvWithRuntimeInfo(t, false)

	err := env.enroll(map[string]string{flagFleetKeyFile: fleetKeyFile})

	require.Error(t, err)
	assertNothingStored(t, env.home)
}

func Test_machineEnroll_sendsNoCredentialsToTheEnrollmentService(t *testing.T) {
	env := newEnrollEnv(t)
	env.config.Set(configuration.AUTHENTICATION_TOKEN, "00000000-0000-0000-0000-000000000000")
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))

	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: deviceToken}))

	assert.Empty(t, env.server.CredentialHeaders())
}

func Test_machineEnroll_controlAuthenticatedClientSendsCredentials(t *testing.T) {
	env := newEnrollEnv(t)
	env.config.Set(configuration.AUTHENTICATION_TOKEN, "00000000-0000-0000-0000-000000000000")

	res, err := env.engine.GetNetworkAccess().GetHttpClient().Post(env.server.URL+"/oauth2/token", "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	_ = res.Body.Close()

	assert.NotEmpty(t, env.server.CredentialHeaders(), "the control: this engine's authenticated client sends credentials")
}

var errDiskFull = errors.New("disk full")

func (e *enrollEnv) failWritesAfterEnrolling(t *testing.T) {
	t.Helper()
	storage := mocks.NewMockStorage(gomock.NewController(t))
	storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	storage.EXPECT().Unlock().Return(nil).AnyTimes()
	storage.EXPECT().Set(gomock.Any(), gomock.Any()).Return(errDiskFull).AnyTimes()
	e.config.SetStorage(storage)
}

func Test_machineEnroll_failedSaveNamesTheClientAndNeverTheKey(t *testing.T) {
	env := newEnrollEnv(t)
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))
	env.failWritesAfterEnrolling(t)

	err := env.enroll(map[string]string{flagDeviceToken: deviceToken})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrolled as client client-1 but the credential could not be stored")
	assert.Contains(t, err.Error(), "ask an admin to revoke the client")
	assert.NotContains(t, err.Error(), "PRIVATE KEY")
	assert.NotContains(t, err.Error(), "private_key_pem")
	assert.ErrorIs(t, err, errDiskFull, "the underlying error is wrapped")
}

func Test_machineEnroll_secondEnrollmentReplacesAndLogsTheOldClient(t *testing.T) {
	env := newEnrollEnv(t)
	logs := &bytes.Buffer{}
	machineID := env.server.RegisterMachine("SERIAL-1")
	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: env.server.IssueDeviceToken(machineID)}))
	first, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	env.config = openFileBackedConfig()
	env.config.Set(configuration.API_URL, env.server.URL)
	logger := zerolog.New(logging.NewScrubbingWriter(zerolog.MultiLevelWriter(logs), logging.GetScrubDictFromConfig(env.config)))
	env.engine.SetLogger(&logger)

	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: env.server.IssueDeviceToken(machineID)}))

	second, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.NotEqual(t, first.ClientID, second.ClientID)
	assert.Contains(t, logs.String(), "replaced the credential of client "+first.ClientID)
	assert.NotContains(t, logs.String(), "PRIVATE KEY")
}

func Test_machineEnroll_failedSaveDoesNotLogAReplacement(t *testing.T) {
	env := newEnrollEnv(t)
	logs := &bytes.Buffer{}
	logger := zerolog.New(logs)
	env.engine.SetLogger(&logger)
	machineID := env.server.RegisterMachine("SERIAL-1")
	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: env.server.IssueDeviceToken(machineID)}))
	first, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	env.failWritesAfterEnrolling(t)

	err = env.enroll(map[string]string{flagDeviceToken: env.server.IssueDeviceToken(machineID)})

	require.ErrorIs(t, err, errDiskFull, "the second enrollment reached the store and failed there")
	assert.NotContains(t, logs.String(), "credential of client "+first.ClientID)
}

func Test_machineEnroll_corruptStoredCredentialDoesNotBlockEnrollment(t *testing.T) {
	env := newEnrollEnv(t)
	env.config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, "{not json")
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))

	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: deviceToken}))

	_, err := machinecredential.Load(openFileBackedConfig())
	assert.NoError(t, err)
}

func Test_machineEnroll_fleetKeyAcceptsAMachineThatComesWithAnError(t *testing.T) {
	env := newEnrollEnv(t)
	machineID := env.server.RegisterMachine("S1")
	fleetKeyFile, fleetKey := writeFleetKey(t)
	env.server.AllowFleetKey(&fleetKey.PublicKey, machineID)
	env.config.AddDefaultValue(configuration.MACHINE_ID, func(configuration.Configuration, any) (any, error) {
		return runtimeinfo.Machine{ID: "stable-id", SerialNumber: "S1"}, errors.New("read problem")
	})

	require.NoError(t, env.enroll(map[string]string{flagFleetKeyFile: fleetKeyFile}))

	_, err := machinecredential.Load(openFileBackedConfig())
	assert.NoError(t, err)
}

func Test_machineEnroll_fleetKeyRejectsNoMachineIDEvenWithASerialNumber(t *testing.T) {
	fleetKeyFile, _ := writeFleetKey(t)
	ctrl := gomock.NewController(t)
	runtimeInfo := mocks.NewMockRuntimeInfo(ctrl)
	runtimeInfo.EXPECT().GetMachineID().Return(runtimeinfo.Machine{SerialNumber: "S1"}, runtimeinfo.ErrNoMachineID)

	_, err := enrollWithFleetKeyFile(t.Context(), runtimeInfo, http.DefaultClient, "http://127.0.0.1:1", fleetKeyFile)

	require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
}

func Test_machineEnroll_failedSaveAfterFleetKeyEnrollmentDoesNotMentionTheDeviceToken(t *testing.T) {
	env := newEnrollEnv(t)
	machineID := env.server.RegisterMachine("SERIAL-42")
	fleetKeyFile, fleetKey := writeFleetKey(t)
	env.server.AllowFleetKey(&fleetKey.PublicKey, machineID)
	env.setMachine(runtimeinfo.Machine{ID: "stable-id", SerialNumber: "SERIAL-42"})
	env.failWritesAfterEnrolling(t)

	err := env.enroll(map[string]string{flagFleetKeyFile: fleetKeyFile})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrolled as client client-1 but the credential could not be stored")
	assert.Contains(t, err.Error(), "created a client for this machine")
	assert.NotContains(t, err.Error(), "before enrolling again")
	assert.NotContains(t, err.Error(), "device token")
	assert.NotContains(t, err.Error(), "PRIVATE KEY")
	assert.NotContains(t, err.Error(), "private_key_pem")
	assert.ErrorIs(t, err, errDiskFull, "the underlying error is wrapped")
}

func newTestEnrollment(t *testing.T) machinecredential.Credential {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	return machinecredential.Credential{ClientID: "client-9", Key: key}
}

func Test_storeEnrollment_persistsEvenWhenTheInvocationIsAlreadyCancelled(t *testing.T) {
	_ = newEnrollEnv(t)
	config := openFileBackedConfig()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	err := storeEnrollment(canceled, time.Minute, config, newTestEnrollment(t), true)

	require.NoError(t, err)
	credential, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, "client-9", credential.ClientID)
}

func Test_storeEnrollment_givesUpWhenAnotherHolderKeepsTheLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().Lock(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ time.Duration) error {
		<-ctx.Done()
		return ctx.Err()
	})
	config := configuration.NewWithOpts()
	config.SetStorage(storage)

	start := time.Now()
	err := storeEnrollment(t.Context(), 50*time.Millisecond, config, newTestEnrollment(t), false)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Contains(t, err.Error(), "enrolled as client client-9 but the credential could not be stored")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func Test_machineEnroll_theEnginesOwnConfigurationSeesTheCredential(t *testing.T) {
	env := newEnrollEnv(t)
	machineID := env.server.RegisterMachine("SERIAL-1")

	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: env.server.IssueDeviceToken(machineID)}))
	first, err := machinecredential.Load(env.engine.GetConfiguration())
	require.NoError(t, err, "a host that authenticates in the same process sees the credential")

	require.NoError(t, env.enroll(map[string]string{flagDeviceToken: env.server.IssueDeviceToken(machineID)}))
	second, err := machinecredential.Load(env.engine.GetConfiguration())
	require.NoError(t, err)
	assert.NotEqual(t, first.ClientID, second.ClientID, "re-enrolling replaces it")
}

func Test_machineEnroll_withoutStorageFailsBeforeSpendingTheDeviceToken(t *testing.T) {
	env := newEnrollEnv(t)
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))
	env.config.SetStorage(nil)

	err := env.enroll(map[string]string{flagDeviceToken: deviceToken})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential cannot be stored")
	assert.Equal(t, 0, env.server.ClientCount(), "the single-use device token is not spent")
}

func Test_machineEnroll_withStorageThatPersistsNothingFailsBeforeSpendingTheDeviceToken(t *testing.T) {
	env := newEnrollEnv(t)
	deviceToken := env.server.IssueDeviceToken(env.server.RegisterMachine("SERIAL-1"))
	env.config.SetStorage(&configuration.EmptyStorage{})

	err := env.enroll(map[string]string{flagDeviceToken: deviceToken})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential cannot be stored")
	assert.Equal(t, 0, env.server.ClientCount(), "the single-use device token is not spent")
}
