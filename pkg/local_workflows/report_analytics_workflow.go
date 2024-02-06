package localworkflows

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/persistence"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var (
	WORKFLOWID_REPORT_ANALYTICS workflow.Identifier = workflow.NewWorkflowIdentifier(reportAnalyticsWorkflowName)

	scanDoneSchemaLoader gojsonschema.JSONLoader
)

const (
	reportAnalyticsWorkflowName      = "analytics.report"
	reportAnalyticsInputDataFlagName = "inputData"
)

// InitReportAnalyticsWorkflow initializes the reportAnalytics workflow before registering it with the engine.
func InitReportAnalyticsWorkflow(engine workflow.Engine) error {
	// initialize workflow configuration
	params := pflag.NewFlagSet(reportAnalyticsWorkflowName, pflag.ExitOnError)
	params.StringP(reportAnalyticsInputDataFlagName, "i", "", "Input data containing scan done event")
	params.Bool(configuration.FLAG_EXPERIMENTAL, false, "enable experimental analytics report command")

	// load json schema for scan done event
	scanDoneSchemaLoader = gojsonschema.NewStringLoader(json_schemas.ScanDoneEventSchema)

	// register workflow with engine
	result, err := engine.Register(WORKFLOWID_REPORT_ANALYTICS, workflow.ConfigurationOptionsFromFlagset(params), reportAnalyticsEntrypoint)

	// don't display in help
	result.SetVisibility(false)
	return err
}

// reportAnalyticsEntrypoint is the entry point for the reportAnalytics workflow.
func reportAnalyticsEntrypoint(invocationCtx workflow.InvocationContext, inputData []workflow.Data) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	logger.Println(reportAnalyticsWorkflowName + " workflow start")

	if !config.GetBool(configuration.FLAG_EXPERIMENTAL) {
		return nil, fmt.Errorf("set `--experimental` flag to enable analytics report command")
	}

	commandLineInput := config.GetString(reportAnalyticsInputDataFlagName)
	if commandLineInput != "" {
		logger.Printf("adding command line input")
		data := workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName),
			"application/json",
			[]byte(commandLineInput),
		)
		inputData = append(inputData, data)
	}
	db, err := getReportAnalyticsDatabase(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get report analytics database")
	}

	for i, input := range inputData {
		logger.Printf(fmt.Sprintf("processing element %d", i))
		documentLoader := gojsonschema.NewBytesLoader(input.GetPayload().([]byte))
		result, validationErr := gojsonschema.Validate(scanDoneSchemaLoader, documentLoader)

		if validationErr != nil {
			err := fmt.Errorf("error validating input at index %d: %w", i, validationErr)
			return nil, err
		}

		if !result.Valid() {
			err := fmt.Errorf("validation failed for input at index %d: %v", i, result.Errors())
			return nil, err
		}

		_, err := appendToOutbox(invocationCtx, db, input.GetPayload().([]byte))
		if err != nil {
			return nil, errors.Wrap(err, "failed to append to outbox")
		}
	}

	err = sendOutbox(invocationCtx, db)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send outbox")
	}
	logger.Println(reportAnalyticsWorkflowName + " workflow end")
	return nil, nil
}

func getReportAnalyticsDatabase(conf configuration.Configuration) (*sql.DB, error) {
	db, err := persistence.GetDatabase(conf, reportAnalyticsWorkflowName)
	return db, err
}

func getReportAnalyticsEndpoint(config configuration.Configuration) string {
	url := fmt.Sprintf("%s/hidden/orgs/%s/analytics?version=2023-11-09~experimental", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))
	return url
}

func appendToOutbox(ctx workflow.InvocationContext, db *sql.DB, payload []byte) (string, error) {
	commit := false
	logger := ctx.GetLogger()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	defer finalizeTx(tx, logger, &commit)

	if err != nil {
		return "", errors.Wrap(err, "failed to start transaction")
	}

	err = createOutboxTable(tx)
	if err != nil {
		return "", errors.Wrap(err, "failed to create outbox table")
	}

	query := "INSERT INTO outbox (id, timestamp, retries, payload) VALUES (?, ?, ?, ?)"
	id := uuid.New()
	_, err = tx.Exec(query, id.String(), time.Now().Unix(), 0, payload)
	if err != nil {
		return "", errors.Wrap(err, "failed to insert into outbox")
	}
	commit = true
	return id.String(), nil
}

func finalizeTx(tx *sql.Tx, logger *log.Logger, commit *bool) {
	if *commit {
		err := tx.Commit()
		if err != nil {
			logger.Println("failed to commit transaction ")
			return
		}
		logger.Println("committed transaction")
	} else {
		err := tx.Rollback()
		if err != nil {
			logger.Println("failed to roll back transaction")
			return
		}
		logger.Println("rolled back transaction")
	}
}

func sendOutbox(ctx workflow.InvocationContext, db *sql.DB) error {
	commit := false
	logger := ctx.GetLogger()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return errors.Wrap(err, "failed to start transaction")
	}
	defer finalizeTx(tx, logger, &commit)

	maxRetries := 3
	query, err := tx.Query("SELECT id, retries, payload FROM outbox WHERE retries < ?", maxRetries)
	if err != nil {
		return errors.Wrap(err, "failed to query outbox")
	}
	defer func() {
		err = query.Close()
		if err != nil {
			logger.Println("failed to close query")
		}
	}()

	for query.Next() {
		var id string
		var payload []byte
		var retries int

		err := query.Scan(&id, &retries, &payload)
		if err != nil {
			return errors.Wrap(err, "failed to scan outbox")
		}

		err = callEndpoint(ctx, payload)
		logger.Println("sent analytics report to endpoint: " + id)
		if err != nil {
			logger.Printf("failed to call endpoint: %v\n", err)
			_, err := tx.Exec("UPDATE outbox SET retries = ? WHERE id = ?", retries+1, id)
			if err != nil {
				return errors.Wrap(err, "failed to update outbox")
			}
			break // stop processing outbox
		}
		_, err = tx.Exec("DELETE FROM outbox WHERE id = ? OR retries >= ?", id, maxRetries)
		logger.Println("updated analytics report in outbox: " + id)
		if err != nil {
			return errors.Wrap(err, "failed to update outbox")
		}
	}
	commit = true
	return nil
}

func createOutboxTable(tx *sql.Tx) error {
	query := "CREATE TABLE IF NOT EXISTS " +
		"outbox (" +
		"id TEXT PRIMARY KEY, " +
		"timestamp INTEGER NOT NULL, " +
		"retries INTEGER DEFAULT 0, " +
		"payload BLOB NOT NULL)"

	_, err := tx.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func callEndpoint(invocationCtx workflow.InvocationContext, payload []byte) error {
	logger := invocationCtx.GetLogger()
	url := getReportAnalyticsEndpoint(invocationCtx.GetConfiguration())

	// Create a request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		logger.Printf("Error creating request: %v\n", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request

	resp, err := invocationCtx.GetNetworkAccess().GetHttpClient().Do(req)
	if err != nil {
		logger.Printf("Error sending request: %v\n", err)
		return err
	}

	if resp.StatusCode != 201 {
		return fmt.Errorf("Error sending request: %v\n", resp.Status)
	}

	defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)
	return nil
}
