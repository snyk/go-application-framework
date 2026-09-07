package toon

// Column describes one tabular TOON field and whether it needs quoting.
type Column struct {
	Name   string
	Quoted bool
}

// Section is a generic concise TOON block for one finding type.
type Section struct {
	Name    string
	Columns []Column
	Rows    [][]string
	Summary string
}
