#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*"
cargo build \
--release \
--bin avalanche-ops-aws \
--bin avalanched-aws \
--bin dev-machine \
--bin subnetctl

./target/release/avalanche-ops-aws --help
./target/release/avalanche-ops-aws apply --help
./target/release/avalanche-ops-aws delete --help
./target/release/avalanche-ops-aws default-spec --help
./target/release/avalanche-ops-aws read-spec --help
./target/release/avalanche-ops-aws check-balances --help
./target/release/avalanche-ops-aws events --help
./target/release/avalanche-ops-aws events update-artifacts --help
./target/release/avalanched-aws --help
./target/release/avalanched-aws backup upload --help
./target/release/avalanched-aws backup download --help
./target/release/dev-machine --help
./target/release/subnetctl --help
