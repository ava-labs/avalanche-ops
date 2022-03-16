#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/examples.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# RUST_LOG=debug cargo run --example aws_cloudformation_ec2_instance_role.rs
cargo run --example aws_cloudformation_ec2_instance_role
cargo run --example aws_cloudformation_vpc
cargo run --example aws_cloudwatch
cargo run --example aws_ec2_key_pair
cargo run --example aws_kms
cargo run --example aws_s3
cargo run --example aws_sts
cargo run --example utils_compress
cargo run --example utils_random

echo "ALL SUCCESS!"

# cargo run --example avalanche_api_avm -- \
# [HTTP RPC ENDPOINT] X-custom152qlr6zunz7nw2kc4lfej3cn3wk46u3002k4w5

# cargo run --example avalanche_api_platform -- \
# [HTTP RPC ENDPOINT] P-custom152qlr6zunz7nw2kc4lfej3cn3wk46u3002k4w5

# cargo run --example avalanche_api_eth -- \
# [HTTP RPC ENDPOINT] 0xc41Cc85E565aBd1Ecdd6d32C72F16E4a4B530157

# cargo run --example avalanche_api_info -- \
# [HTTP RPC ENDPOINT]
