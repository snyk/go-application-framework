#!/usr/bin/env bash

API_SPEC_PATH=$(realpath ../dragonfly)
API_SPEC_BRANCH=${API_SPEC_BRANCH:-main}

echo --------------------------------------------------------
echo Updating local findings from dragonfly!
echo
echo Path:   $API_SPEC_PATH
echo Branch: $API_SPEC_BRANCH
echo --------------------------------------------------------

# Check if the directory exists
if [[ ! -d "$API_SPEC_PATH" ]]; then
  # Create the directory if it doesn't exist
  git clone git@github.com:snyk/dragonfly.git $API_SPEC_PATH
fi

cd $API_SPEC_PATH
git checkout $API_SPEC_BRANCH
git pull

# Update dependencies
npm ci
# Trigger build of dragonfly project
npm run build

# Return to project directory
cd -

# Vendor OpenAPI build artefacts for use in cue
cp -r $API_SPEC_PATH/tsp-output/@typespec/openapi3/ ./internal/cueutils/source/openapi/rest

make generate