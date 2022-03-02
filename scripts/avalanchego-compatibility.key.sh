#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/avalanchego-compatibility.key.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

###
cargo run --example avalanche_key -- ./artifacts/ewoq.key.json

###
pushd ./avalanchego-compatibility
go run \
./key/main.go > /tmp/test.key.json
popd
cargo run --example avalanche_key -- /tmp/test.key.json

###
echo "ALL SUCCESS!"
