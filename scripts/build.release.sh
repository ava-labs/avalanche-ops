#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*" or workspaces
cargo build \
--release \
--bin avalancheup-aws \
--bin avalanched-aws \
--bin staking-key-cert-s3-downloader

./target/release/avalancheup-aws --help
./target/release/avalancheup-aws default-spec --help
./target/release/avalancheup-aws apply --help
./target/release/avalancheup-aws delete --help

./target/release/avalanched-aws --help

./target/release/staking-key-cert-s3-downloader --help
