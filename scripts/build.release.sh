#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*" or workspaces
cargo build \
--release \
--bin avalanche-kms \
--bin avalanched-aws \
--bin avalancheup-aws \
--bin blizzard-aws \
--bin blizzardup-aws \
--bin staking-key-cert-s3-downloader \
--bin staking-signer-key-s3-downloader \
--bin devnet-faucet

./target/release/avalanche-kms --help

./target/release/avalanched-aws --help

./target/release/avalancheup-aws --help
./target/release/avalancheup-aws default-spec --help
./target/release/avalancheup-aws apply --help
./target/release/avalancheup-aws delete --help

./target/release/blizzard-aws --help

./target/release/blizzardup-aws --help
./target/release/blizzardup-aws default-spec --help
./target/release/blizzardup-aws apply --help
./target/release/blizzardup-aws delete --help

./target/release/staking-key-cert-s3-downloader --help

./target/release/devnet-faucet --help
