#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/example.run.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# RUST_LOG=debug cargo run --example aws_cloudformation
cargo run --example aws_cloudformation
cargo run --example aws_ec2_key_pair
cargo run --example aws_kms
cargo run --example aws_s3
cargo run --example aws_sts
cargo run --example cert

echo "ALL SUCCESS!"
