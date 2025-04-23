#!/usr/bin/env bash

set -ux

project_dir=$(dirname $(realpath $0))

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT

filename=$1
shift

snyk depgraph --json --file=$filename "$@" >$tmpdir/depgraph.json
rc=$?
if [ "$rc" = "2" ]; then
  exit $rc
fi

set -e

cat >$tmpdir/req.json <<EOF
{
  "depGraph": $(cat $tmpdir/depgraph.json),
  "foundProjectCount": 1,
  "targetFileRelativePath": "$filename"
}
EOF

cat $tmpdir/req.json

go run $project_dir/main.go $tmpdir/req.json
