#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*" or workspaces
cargo build \
--release \
--bin avalanche-ops-aws \
--bin avalanched-aws \
--bin dev-machine-aws \
--bin subnetctl

BIN_PATH=./target/release
${BIN_PATH}/avalanche-ops-aws --help
${BIN_PATH}/avalanche-ops-aws default-spec --help
${BIN_PATH}/avalanche-ops-aws apply --help
${BIN_PATH}/avalanche-ops-aws delete --help
${BIN_PATH}/avalanche-ops-aws read-spec --help
${BIN_PATH}/avalanche-ops-aws check-balances --help
${BIN_PATH}/avalanche-ops-aws events --help
${BIN_PATH}/avalanche-ops-aws events update-artifacts --help

${BIN_PATH}/avalanched-aws --help
${BIN_PATH}/avalanched-aws backup upload --help
${BIN_PATH}/avalanched-aws backup download --help

${BIN_PATH}/dev-machine-aws --help
${BIN_PATH}/dev-machine-aws default-spec --help
${BIN_PATH}/dev-machine-aws apply --help
${BIN_PATH}/dev-machine-aws delete --help

${BIN_PATH}/subnetctl --help
${BIN_PATH}/subnetctl add --help
${BIN_PATH}/subnetctl create --help
${BIN_PATH}/subnetctl get-utxos --help
${BIN_PATH}/subnetctl vm-id --help
