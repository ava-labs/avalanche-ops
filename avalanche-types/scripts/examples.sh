#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ ./scripts/examples.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

cargo run --example cert -- /tmp/test.insecure.key /tmp/test.insecure.cert

cargo run --example key_info_gen -- 9999 /tmp/key.json

cargo run --example key_info_load_avax -- PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN 1
cargo run --example key_info_load_avax -- PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN 9999
cargo run --example key_info_load_avax -- PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67 1
cargo run --example key_info_load_avax -- PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67 9999

cargo run --example key_info_load_eth -- 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027 1
cargo run --example key_info_load_eth -- 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027 9999
cargo run --example key_info_load_eth -- e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852 1
cargo run --example key_info_load_eth -- e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852 9999

cargo run --example key_info_validate -- ./artifacts/ewoq.key.json 9999
