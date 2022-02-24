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
--bin avalanched-aws \
--bin dev-machine

./target/release/avalanche-ops-nodes-aws --help
./target/release/avalanched-aws --help
./target/release/avalanched-aws upload-backup --help
./target/release/avalanched-aws download-backup --help
./target/release/dev-machine --help
