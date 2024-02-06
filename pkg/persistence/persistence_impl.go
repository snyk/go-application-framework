package persistence

import (
	"database/sql"
	"path/filepath"

	"github.com/pkg/errors"
	_ "modernc.org/sqlite"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// GetDatabase returns a database connection for the given name.
func GetDatabase(conf configuration.Configuration, name string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", filepath.Join(conf.GetString(configuration.CACHE_PATH), "db_"+name))
	if err != nil {
		return nil, errors.Wrap(err, "failed to open database")
	}
	return db, nil
}
