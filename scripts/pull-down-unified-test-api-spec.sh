#!/usr/bin/env bash

TEST_API_DIR=$(realpath ./internal/api/test-api)

# Data source
API_SPEC_PATH=$TEST_API_DIR/unified-test-repo
API_SPEC_BRANCH=${API_SPEC_BRANCH:-main}

# Outputs
TEST_API_GENERATED=$TEST_API_DIR/unified-test-spec
GENERATE_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)


echo --------------------------------------------------------
echo Updating local spec from unified test repo!
echo
echo Path:   $API_SPEC_PATH
echo Branch: $API_SPEC_BRANCH
echo Date:   $GENERATE_DATE
echo --------------------------------------------------------

# Check if the directory exists
if [[ ! -d "$API_SPEC_PATH" ]]; then
  # Create the directory if it doesn't exist
  git clone git@github.com:snyk/test-api-shim.git $API_SPEC_PATH
fi

cd $API_SPEC_PATH
git checkout $API_SPEC_BRANCH
API_COMMIT=$(git rev-parse HEAD)
git pull

# Return to project directory
cd -

# place OpenAPI build artifacts
mkdir -p $TEST_API_GENERATED

cp $API_SPEC_PATH/internal/api/closed-beta/versions/2024-10-15/spec.yaml $TEST_API_GENERATED/unified-test-api.yaml
echo $GENERATE_DATE $API_SPEC_BRANCH $API_COMMIT > $TEST_API_GENERATED/generated.txt
