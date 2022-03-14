#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/install.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

cargo install --verbose \
--path . \
--bin avalanche-ops-aws \
--bin avalanched-aws \
--bin dev-machine \
--bin subnetctl

# e.g., "${HOME}/.cargo/bin" should in local ${PATH}
avalanche-ops-aws --help
avalanched-aws --help
dev-machine --help
subnetctl --help
