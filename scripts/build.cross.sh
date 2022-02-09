#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.cross.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# TODO: this does not work on mac
# "aesni-x86_64-elf.S: No such file or directory (os error 2)"
#
# rustup target add x86_64-unknown-linux-gnu
# cargo build \
# --release \
# --bin avalanche-ops-nodes-aws \
# --bin avalanched-aws \
# --target x86_64-unknown-linux-gnu

# rustup target add x86_64-unknown-linux-musl
# cargo build \
# --release \
# --bin avalanche-ops-nodes-aws \
# --bin avalanched-aws \
# --target x86_64-unknown-linux-musl

# TODO: not working
# ref. https://github.com/cross-rs/cross/issues/510
# ref. https://github.com/cross-rs/cross/issues/229
# cargo install cross
# cargo install --version 0.1.16 cross
cross build \
--release \
--bin avalanche-ops-nodes-aws \
--bin avalanched-aws \
--target x86_64-unknown-linux-gnu
