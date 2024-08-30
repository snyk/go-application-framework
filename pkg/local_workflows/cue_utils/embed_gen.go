package cue_utils

import (
	"embed"
)

//go:generate npm run build

//go:generate cue import -p testapi ../../tsp-output/@typespec/openapi3/rest/test.spec.yaml -f -o schemas/testapi.cue
//go:generate cue import -p v1_test_dep_graph ../../tsp-output/@typespec/openapi3/v1/test_dep_graph.spec.yaml -f -o schemas/v1_test_dep_graph.cue
//go:generate cue import -p cli_test_managed ../../tsp-output/@typespec/openapi3/cli/test_managed.spec.yaml -f -o schemas/cli_test_managed.cue
//go:generate cue import -p sarif ../../api/compat/cli/code/sarif-schema-2.1.0.json -f -o schemas/sarif.cue

//go:embed convert
//go:embed cue.mod
//go:embed schemas
var embeddedFilesystem embed.FS
