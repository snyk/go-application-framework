package reportanalytics

import (
	"database/sql"
	"path/filepath"

	"github.com/pkg/errors"
	_ "modernc.org/sqlite"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// GetDatabase returns a database connection for the given name.
func GetDatabase(conf configuration.Configuration, prefix, name string) (*sql.DB, error) {
	cachePath := conf.GetString(configuration.CACHE_PATH)

	dbFile := filepath.Join(cachePath, prefix+"_"+name+".db")

	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open database")
	}
	return db, nil
}
