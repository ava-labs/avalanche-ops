#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*"
cargo build \
--release \
--bin avalanche-ops-nodes-aws \
--bin avalanched-aws

./target/release/avalanche-ops-nodes-aws --help
./target/release/avalanched-aws --help
