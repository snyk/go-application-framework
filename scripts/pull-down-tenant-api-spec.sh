#!/usr/bin/env bash


TENANTS_API_DIR=$(realpath ./pkg/apiclients/tenantsapi)

# Data source
API_SPEC_PATH=$(mktemp -d)
API_SPEC_BRANCH=${API_SPEC_BRANCH:-main}
trap "rm -rf $API_SPEC_PATH" EXIT

# Outputs
TENANTS_API_GENERATED=$TENANTS_API_DIR/2024-10-15

GENERATE_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION="2024-10-15"
echo --------------------------------------------------------
echo Updating API Spec for tenants-service
echo
echo Path:   $API_SPEC_PATH
echo Branch: $API_SPEC_BRANCH
echo Date:   $GENERATE_DATE
echo --------------------------------------------------------

# Check if the directory exists

git clone git@github.com:snyk/tenants-service.git $API_SPEC_PATH


cd $API_SPEC_PATH
git checkout $API_SPEC_BRANCH
API_COMMIT=$(git rev-parse HEAD)
git pull

# Return to project directory
cd -

# place OpenAPI build artifacts
mkdir -p $TENANTS_API_GENERATED

# Vendor OpenAPI build artefacts for use in the policy API client
cp $API_SPEC_PATH/internal/api/rest/versions/$VERSION/spec.yaml $TENANTS_API_GENERATED/spec.yaml

echo "Generated" $GENERATE_DATE $API_SPEC_BRANCH $API_COMMIT > $TENANTS_API_GENERATED/generated.txt
