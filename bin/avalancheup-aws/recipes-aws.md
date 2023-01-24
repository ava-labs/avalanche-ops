

To download from release, visit https://github.com/ava-labs/avalanche-ops/releases.

To compile from source:

```bash
# if you don't have rust on your local
curl -sSf https://sh.rustup.rs | sh -s -- -y \
&& . ${HOME}/.cargo/env \
&& rustc --version && cargo --version \
&& which rustc && which cargo
```

```bash
# to build binaries
./scripts/build.release.sh
```

```bash
# 1. simple, default spot + elastic
/home/ubuntu/avalanche-ops/target/release/avalancheup-aws default-spec --network-name custom
```

```bash
# 2. simple, subnet-evm
/home/ubuntu/avalanche-ops/target/release/avalancheup-aws default-spec \
--install-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--install-artifacts-plugin-local-dir ${AVALANCHE_PLUGIN_DIR_PATH} \
--instance-mode=on-demand \
--ip-mode=elastic \
--network-name custom \
--keys-to-generate 5 \
--subnet-evms 1
```

```bash
AWS_VOLUME_PROVISIONER_BIN_PATH=/tmp/aws-volume-provisioner-new
AWS_IP_PROVISIONER_BIN_PATH=/tmp/aws-ip-provisioner-new
AVALANCHE_TELEMETRY_CLOUDWATCH_BIN_PATH=/tmp/avalanche-telemetry-cloudwatch
AVALANCHE_CONFIG_BIN_PATH=/home/ubuntu/avalanche-ops/target/release/avalanche-config
AVALANCHED_BIN_PATH=/home/ubuntu/avalanche-ops/target/release/avalanched-aws
AVALANCHE_BIN_PATH=/home/ubuntu/go/src/github.com/ava-labs/avalanchego/build/avalanchego
AVALANCHE_PLUGIN_DIR_PATH=/home/ubuntu/go/src/github.com/ava-labs/avalanchego/build/plugin

cd /home/ubuntu/avalanche-ops
rm -rf /home/ubuntu/subnet-evm-test-keys-ap-northeast-2
/home/ubuntu/avalanche-ops/target/release/avalancheup-aws default-spec \
--region ap-northeast-2 \
--install-artifacts-aws-volume-provisioner-local-bin ${AWS_VOLUME_PROVISIONER_BIN_PATH} \
--install-artifacts-aws-ip-provisioner-local-bin ${AWS_IP_PROVISIONER_BIN_PATH} \
--install-artifacts-avalanche-telemetry-cloudwatch-local-bin ${AVALANCHE_TELEMETRY_CLOUDWATCH_BIN_PATH} \
--install-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--install-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--install-artifacts-plugin-local-dir ${AVALANCHE_PLUGIN_DIR_PATH} \
--instance-mode=on-demand \
--ip-mode=elastic \
--network-name custom \
--keys-to-generate 50 \
--keys-to-generate-type hot \
--key-files-dir /home/ubuntu/subnet-evm-test-keys-ap-northeast-2 \
--subnet-evms 1
```
