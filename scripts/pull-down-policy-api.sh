#!/usr/bin/env bash

API_SPEC_PATH=$(realpath ../policy-service)
API_SPEC_BRANCH=${API_SPEC_BRANCH:-main}
GENERATE_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION="2024-10-15"
echo --------------------------------------------------------
echo Updating API Spec for policy-service
echo
echo Path:   $API_SPEC_PATH
echo Branch: $API_SPEC_BRANCH
echo Date:   $GENERATE_DATE
echo --------------------------------------------------------

# Check if the directory exists
if [[ ! -d "$API_SPEC_PATH" ]]; then
  # Create the directory if it doesn't exist
  git clone git@github.com:snyk/policy-service.git $API_SPEC_PATH
fi

cd $API_SPEC_PATH
git checkout $API_SPEC_BRANCH
API_COMMIT=$(git rev-parse HEAD)
git pull

# Return to project directory
cd -

# Vendor OpenAPI build artefacts for use in cue
cp -r $API_SPEC_PATH/internal/api/rest/versions/$VERSION/spec.yaml ./internal/api/policy/$VERSION/spec.yaml

echo "Generated" $GENERATE_DATE $API_SPEC_BRANCH $API_COMMIT
