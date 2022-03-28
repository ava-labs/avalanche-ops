#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/examples.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

cargo run --example compress
cargo run --example id
cargo run --example random

echo "ALL SUCCESS!"
