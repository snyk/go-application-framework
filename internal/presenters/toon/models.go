package toon

// SCAView is the concise SCA section projected from UFM test results.
type SCAView struct {
	Rows    []SCARow
	Summary string
}

// SCARow is one deduplicated open-source vulnerability row.
type SCARow struct {
	ID       string
	Severity string
	Pkg      string
	Fixable  string
}

// SecretsView is the concise Secrets section projected from UFM test results.
type SecretsView struct {
	Rows    []SecretsRow
	Summary string
}

// SecretsRow is one detected secret row.
type SecretsRow struct {
	Rule     string
	Severity string
	File     string
	Line     int
}
