package toon

type colSpec[T any] struct {
	Name   string
	Quoted bool
	Value  func(T) string
}

func buildSection[T any](name string, items []T, cols []colSpec[T], summary string) Section {
	section := Section{
		Name:    name,
		Summary: summary,
		Columns: make([]Column, len(cols)),
		Rows:    make([][]string, len(items)),
	}
	for i, col := range cols {
		section.Columns[i] = Column{Name: col.Name, Quoted: col.Quoted}
	}
	for i, item := range items {
		row := make([]string, len(cols))
		for j, col := range cols {
			row[j] = col.Value(item)
		}
		section.Rows[i] = row
	}
	return section
}
