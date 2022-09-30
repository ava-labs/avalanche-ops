#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.x86_64-linux-musl.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# https://github.com/clux/muslrust
docker pull clux/muslrust
docker run -v $PWD:/volume --rm -t clux/muslrust \
cargo build \
--release \
--bin avalanched-aws \
--bin avalancheup-aws \
--bin blizzard-aws \
--bin blizzardup-aws \
--bin staking-key-cert-s3-downloader \
--target x86_64-unknown-linux-musl

BIN_PATH=./target/x86_64-unknown-linux-musl/release
${BIN_PATH}/avalancheup-aws --help || true

# e.g.,
# AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
