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

cd -

# Vendor OpenAPI build artefacts for use in cue
cp -r $API_SPEC_PATH/tsp-output/@typespec/openapi3/ ./internal/cue_utils/source/openapi

cd ./internal/cue_utils
go generate