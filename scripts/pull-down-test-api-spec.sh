#!/usr/bin/env bash

API_SPEC_PATH=../dragonfly
# Navigate to repo
cd $API_SPEC_PATH
git checkout main
git pull

# Update dependencies
npm ci
# Trigger build of dragonfly project
npm run build

# Return to project directory
cd -

# Vendor OpenAPI build artefacts for use in cue
cp -r $API_SPEC_PATH/tsp-output/@typespec/openapi3/ ./internal/cue_utils/source/openapi
# Import types for go
cp $API_SPEC_PATH/tsp-output/go/typespec_gen.go ./internal/dragonfly/dragonfly.go

# Rename imported go types
# In the future the package name will be configurable
sed -i "" 's/package\ presentation/package\ dragonfly/g' internal/dragonfly/dragonfly.go

cd ./internal/cue_utils
go generate