#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/avalanchego-compatibility.node-id.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

pushd ./avalanchego-compatibility
go run \
./node-id/main.go \
../artifacts/staker1.insecure.key ../artifacts/staker1.insecure.crt
popd

echo "ALL SUCCESS!"
