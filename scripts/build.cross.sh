#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.cross.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# ARCHS=amd64 ./scripts/build.cross.sh
# ARCHS=arm64 ./scripts/build.cross.sh
#
# TODO: "arm64" not working...
# "Compiling aws-config v0.6.0" gets killed 
#
DEFAULT_ARCHS='amd64'
ARCHS=${ARCHS:-$DEFAULT_ARCHS}

# TODO: support darwin?
DEFAULT_OS='linux'

for arch in ${ARCHS}; do
  for os in ${DEFAULT_OS}; do
    echo "=== Building arch=${arch}, os=${os} ==="
    if [[ "${os}" == "linux" ]]; then
      docker build \
      --progress plain \
      --platform linux/${arch} \
      -t avalanche-ops.${arch}.${os}:latest \
      -f ./scripts/Dockerfile.build.ubuntu \
      .

      rm -rf ./target/${arch}.${os}
      mkdir -p ./target/${arch}.${os}
      docker cp $(docker create --rm avalanche-ops.${arch}.${os}:latest):/avalanche-ops/target/release/avalanche-ops-nodes-aws ./target/${arch}.${os}/
      docker cp $(docker create --rm avalanche-ops.${arch}.${os}:latest):/avalanche-ops/target/release/avalanched-aws ./target/${arch}.${os}/
      find ./target/${arch}.${os}
    fi
  done
done





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
# cross build \
# --release \
# --bin avalanche-ops-nodes-aws \
# --bin avalanched-aws \
# --target x86_64-unknown-linux-gnu
