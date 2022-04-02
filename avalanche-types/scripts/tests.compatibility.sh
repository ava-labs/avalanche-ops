#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/tests.compatibility.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

###
pushd ./compatibility
go run ./key-info-gen/main.go 9999 /tmp/test.key.json
go run ./key-info-validate/main.go /tmp/test.key.json 9999
popd
cargo run --example soft_key_info_validate -- /tmp/test.key.json 9999

###
cargo run --example soft_key_info_gen -- 9999 /tmp/test.key.json
pushd ./compatibility
go run ./key-info-validate/main.go /tmp/test.key.json 9999
popd

###
pushd ./compatibility
go run ./key-infos-validate/main.go ../artifacts/test.insecure.secp256k1.key.infos.json
popd

###
pushd ./compatibility
# copied from "avalanchego/staking/local/staking1.key,crt"
go run ./node-id-load/main.go ../artifacts/staker1.insecure.key ../artifacts/staker1.insecure.crt
go run ./node-id-load/main.go ../artifacts/staker2.insecure.key ../artifacts/staker2.insecure.crt
go run ./node-id-load/main.go ../artifacts/staker3.insecure.key ../artifacts/staker3.insecure.crt
go run ./node-id-load/main.go ../artifacts/staker4.insecure.key ../artifacts/staker4.insecure.crt
go run ./node-id-load/main.go ../artifacts/staker5.insecure.key ../artifacts/staker5.insecure.crt
# generated by "examples/cert.rs"
go run ./node-id-load/main.go ../artifacts/test.insecure.key ../artifacts/test.insecure.crt
popd

###
rm -f /tmp/test.insecure.key /tmp/test.insecure.cert
cargo run --example cert -- /tmp/test.insecure.key /tmp/test.insecure.cert
pushd ./compatibility
go run ./node-id-load/main.go /tmp/test.insecure.key /tmp/test.insecure.cert
popd

###
pushd ./compatibility
go run ./cert-gen/main.go /tmp/test.insecure.key /tmp/test.insecure.cert
go run ./node-id-load/main.go /tmp/test.insecure.key /tmp/test.insecure.cert
popd
cargo run --example cert -- /tmp/test.insecure.key /tmp/test.insecure.cert

###
echo "ALL SUCCESS!"
