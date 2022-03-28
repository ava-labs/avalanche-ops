#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ ./scripts/examples.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# RUST_LOG=debug cargo run --example cloudformation_ec2_instance_role
cargo run --example cloudformation_ec2_instance_role
cargo run --example cloudformation_vpc
cargo run --example cloudwatch
cargo run --example ec2_key_pair
cargo run --example kms
cargo run --example s3
cargo run --example sts

echo "ALL SUCCESS!"
