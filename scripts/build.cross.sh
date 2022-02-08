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

# TODO: not working
# ref. https://github.com/cross-rs/cross/issues/510
# cargo install cross
cross build \
--release \
--bin avalanche-ops-nodes-aws \
--bin avalanched-aws \
--target x86_64-unknown-linux-gnu
