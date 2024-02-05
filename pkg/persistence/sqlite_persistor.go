package persistence

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

var _ Persistor = (*SqlitePersistor)(nil)

// SqlitePersistor is a persistence layer that uses SQLite.
type SqlitePersistor struct {
	dsn string
	db  *sql.DB
}

// DsnOpt is an option for NewSqlitePersistor that sets the DSN of the database.
type DsnOpt struct {
	dsn string
}

type defaultPersistable struct {
	id       PersistableID
	status   PersistableStatus
	category PersistableCategory
	payload  []byte
}

func (d defaultPersistable) ID() PersistableID {
	return d.id
}

func (d defaultPersistable) Status() PersistableStatus {
	return d.status
}

func (d defaultPersistable) Category() PersistableCategory {
	return d.category
}

func (d defaultPersistable) String() string {
	return fmt.Sprint("id: ", d.id, " status: ", d.status, " category: ", d.category)
}

func (d defaultPersistable) Bytes() []byte {
	return d.payload
}

func (o DsnOpt) execute(p *SqlitePersistor) error {
	p.dsn = o.dsn
	return p.initializeDatabase()
}

// Create creates a new object in the persistence layer and returns the UUID of the created object.
func (p *SqlitePersistor) Create(obj Persistable, category PersistableCategory) (PersistableID, error) {
	if p.db == nil {
		return "", fmt.Errorf("database not initialized")
	}

	// insert obj into database
	query := "INSERT INTO persistables (id, status, category, payload) VALUES (?, ?, ?, ?)"
	_, err := p.db.Exec(query, obj.ID(), obj.Status(), category, obj.Bytes())
	if err != nil {
		return "", fmt.Errorf("error inserting object into database: %w", err)
	}

	return obj.ID(), nil
}

func (p *SqlitePersistor) initializeDatabase() error {
	var db *sql.DB
	var err error
	if p.db == nil {
		db, err = sql.Open("sqlite", p.dsn)
		if err != nil {
			return fmt.Errorf("error opening database: %w", err)
		}
	}
	if err = db.Ping(); err != nil {
		return fmt.Errorf("error pinging database: %w", err)
	}
	p.db = db

	_, err = p.db.Exec("CREATE TABLE IF NOT EXISTS persistables (id TEXT, status INTEGER, category TEXT, payload BLOB)")
	if err != nil {
		return err
	}
	return nil
}

func (p *SqlitePersistor) Delete(id PersistableID, category PersistableCategory) error {
	//TODO implement me
	panic("implement me")
}

// Get returns an object from the persistence layer.
func (p *SqlitePersistor) Get(id PersistableID, category PersistableCategory) (Persistable, error) {
	if p.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	row := p.db.QueryRow("SELECT status, payload FROM persistables WHERE id = ? AND category = ?", id, category)
	var status PersistableStatus
	var payload []byte
	err := row.Scan(&status, &payload)
	if err != nil {
		return nil, fmt.Errorf("error getting object from database: %w", err)
	}
	return defaultPersistable{
		id:       id,
		status:   status,
		category: category,
		payload:  payload,
	}, nil
}

func (p *SqlitePersistor) Update(obj Persistable, category PersistableCategory) error {
	//TODO implement me
	panic("implement me")
}

func (p *SqlitePersistor) GetOpenByCategory(category PersistableCategory) ([]Persistable, error) {
	//TODO implement me
	panic("implement me")
}
