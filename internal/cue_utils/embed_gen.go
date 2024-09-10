package cue_utils

import (
	"embed"
)

//go:generate echo "Importing CUE packages"

//go:generate cue import -p testapi ./source/openapi/test.spec.yaml -f -o schemas/testapi.cue
//go:generate cue import -p v1_test_dep_graph ./source/openapi/v1/test_dep_graph.spec.yaml -f -o schemas/v1_test_dep_graph.cue
//go:generate cue import -p cli_test_managed ./source/openapi/cli/test_managed.spec.yaml -f -o schemas/cli_test_managed.cue
//go:generate cue import -p sarif ./source/sarif-schema-2.1.0.json -f -o schemas/sarif.cue

//go:embed convert
//go:embed cue.mod
//go:embed schemas
//go:embed templates
var EmbeddedFilesystem embed.FS
