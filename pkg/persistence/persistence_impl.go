package persistence

import "fmt"

// PersistableID is the type of the UUID of a persistable object.
type PersistableID string

// PersistableStatus is the type of the status of a persistable object.
type PersistableStatus int

// PersistableCategory is the type of the category of a persistable object.
type PersistableCategory string

const (
	// Open is the status of an object that is open.
	Open PersistableStatus = 0
	// Processed is the status of an object that has been processed
	Processed PersistableStatus = 1
	// MarkedForDeletion is the status of an object that has been marked for deletion
	MarkedForDeletion PersistableStatus = 2
)

// Persistable is an interface for objects that can be persisted.
type Persistable interface {
	// ID returns the UUID of the object.
	ID() PersistableID
	Status() PersistableStatus
	Category() PersistableCategory
	fmt.Stringer
	Bytes() []byte
}

// SqlitePersistorOpts is an interface for options that can be passed to NewPersistor.
type SqlitePersistorOpts interface {
	execute(p *SqlitePersistor) error
}

// Persistor is an interface for a persistence layer.
type Persistor interface {
	// Create creates a new object in the persistence layer and returns the UUID of the created object.
	Create(obj Persistable, category PersistableCategory) (PersistableID, error)

	// Delete deletes an object from the persistence layer.
	Delete(id PersistableID, category PersistableCategory) error

	// Get returns an object from the persistence layer.
	Get(id PersistableID, category PersistableCategory) (Persistable, error)

	// Update updates an object in the persistence layer.
	Update(obj Persistable, category PersistableCategory) error

	// GetOpenByCategory returns all open objects from the persistence layer.
	GetOpenByCategory(category PersistableCategory) ([]Persistable, error)
}

// NewSqlitePersistor creates a new Persistor with the given options.
func NewSqlitePersistor(options ...SqlitePersistorOpts) *SqlitePersistor {
	p := &SqlitePersistor{}
	for _, opt := range options {
		err := opt.execute(p)
		if err != nil {
			return nil
		}
	}
	return p
}
