package persistence

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Create(t *testing.T) {
	id, _ := createPersistableForTest(t)

	require.Equal(t, "id", string(id))
}

func createPersistableForTest(t *testing.T) (PersistableID, *SqlitePersistor) {
	p := &defaultPersistable{
		id:       "id",
		status:   Open,
		category: "category",
		payload:  []byte("payload"),
	}
	opt := DsnOpt{
		dsn: t.TempDir() + "/test.db",
	}

	persistor := NewSqlitePersistor(opt)
	id, err := persistor.Create(p, "category")
	require.NoError(t, err)

	return id, persistor
}

func Test_Get(t *testing.T) {
	id, persistor := createPersistableForTest(t)
	require.Equal(t, "id", string(id))

	obj, err := persistor.Get(id, "category")

	require.NoError(t, err)
	require.Equal(t, []byte("payload"), obj.Bytes())
	require.Equal(t, id, obj.ID())
	require.Equal(t, Open, obj.Status())
	require.Equal(t, PersistableCategory("category"), obj.Category())
}
