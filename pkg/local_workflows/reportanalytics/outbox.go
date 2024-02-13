package reportanalytics

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// GetReportAnalyticsOutboxDatabase returns the database for the outbox.
func GetReportAnalyticsOutboxDatabase(conf configuration.Configuration) (*sql.DB, error) {
	db, err := GetDatabase(conf, "report_analytics", "outbox")
	if err != nil {
		return db, errors.Wrap(err, "failed to get database")
	}
	return db, nil
}

// AppendToOutbox appends a new analytics entry to the outbox.
func AppendToOutbox(ctx workflow.InvocationContext, db *sql.DB, payload []byte) (string, error) {
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

func createOutboxTable(tx *sql.Tx) error {
	query := "CREATE TABLE IF NOT EXISTS " +
		"outbox (" +
		"id TEXT PRIMARY KEY, " +
		"timestamp INTEGER NOT NULL, " +
		"retries INTEGER DEFAULT 0, " +
		"payload BLOB NOT NULL)"

	_, err := tx.Exec(query)
	if err != nil {
		return errors.Wrap(err, "failed to create outbox table")
	}
	return nil
}

// SendOutbox sends outbox to the endpoint.
func SendOutbox(ctx workflow.InvocationContext, db *sql.DB, contentType string) error {
	commit := false
	logger := ctx.GetLogger()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return errors.Wrap(err, "failed to start transaction")
	}
	defer finalizeTx(tx, logger, &commit)

	maxRetries := 100
	rows, err := tx.Query("SELECT id, retries, payload FROM outbox WHERE retries < ?", maxRetries)
	if err != nil {
		return errors.Wrap(err, "failed to query outbox")
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id string
		var payload []byte
		var retries int

		err = rows.Scan(&id, &retries, &payload)
		if err != nil {
			return errors.Wrap(err, "failed to scan outbox")
		}

		err = callEndpoint(ctx, payload, contentType)
		logger.Println("sent analytics report to endpoint: " + id)
		if err != nil {
			logger.Printf("failed to call endpoint: %v\n", err)
			_, err2 := tx.Exec("UPDATE outbox SET retries = ? WHERE id = ?", retries+1, id)
			if err2 != nil {
				return errors.Wrap(err, "failed to update outbox")
			}
			break // stop processing outbox
		}
		timeout := time.Now().Add(-time.Hour * 24 * 5).Unix()
		_, err = tx.Exec(
			"DELETE FROM outbox WHERE id = ? OR retries >= ? OR timestamp < ?",
			id,
			maxRetries,
			timeout,
		)
		logger.Println("updated analytics report in outbox: " + id)
		if err != nil {
			return errors.Wrap(err, "failed to update outbox")
		}
	}
	if rows.Err() != nil {
		return errors.Wrap(err, "failed to iterate outbox")
	}
	commit = true
	return nil
}
