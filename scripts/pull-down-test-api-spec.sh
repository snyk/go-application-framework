#!/usr/bin/env bash

TEST_API_DIR=$(realpath ./pkg/apiclients/testapi)

# Data source
API_SPEC_PATH=$(mktemp -d)
API_SPEC_BRANCH=${API_SPEC_BRANCH:-main}
trap "rm -rf $API_SPEC_PATH" EXIT

# Outputs
TEST_API_GENERATED=$TEST_API_DIR/2024-10-15
GENERATE_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo --------------------------------------------------------
echo Updating local spec from unified test repo!
echo
echo Path:   $API_SPEC_PATH
echo Branch: $API_SPEC_BRANCH
echo Date:   $GENERATE_DATE
echo --------------------------------------------------------

# Fetch the spec's repo
git clone git@github.com:snyk/test-api-shim.git $API_SPEC_PATH

cd $API_SPEC_PATH
git checkout $API_SPEC_BRANCH
API_COMMIT=$(git rev-parse HEAD)
git pull

# Return to project directory
cd -

# place OpenAPI build artifacts
mkdir -p $TEST_API_GENERATED

# copy beta API spec
# cp $API_SPEC_PATH/internal/api/closed-beta/versions/2024-10-15/spec.yaml $TEST_API_GENERATED/spec.yaml

# copy public API spec
cp $API_SPEC_PATH/internal/api/public/versions/2024-10-15/spec.yaml $TEST_API_GENERATED/spec.yaml

echo $GENERATE_DATE $API_SPEC_BRANCH $API_COMMIT > $TEST_API_GENERATED/generated.txt
