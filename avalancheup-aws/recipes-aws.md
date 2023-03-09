

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
# 1. simple, default spot instance + elastic IP
# all plugins/binaries are downloaded automatic in the hosts
avalancheup-aws default-spec --network-name custom
```

```bash
# 2. simple, default spot instance + elastic IP, subnet-evm
# all plugins/binaries are downloaded automatic in the hosts
avalancheup-aws default-spec --network-name custom --subnet-evms 1
```

```bash
# 3. simple, subnet-evm with custom binaries
# some plugins/binaries are downloaded automatic from S3 to the hosts
avalancheup-aws default-spec \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGIN_DIR_PATH} \
--instance-mode=on-demand \
--ip-mode=elastic \
--network-name custom \
--keys-to-generate 5 \
--subnet-evms 1
```

```bash
# 4. advanced, subnet-evm with custom binaries
# all plugins/binaries are downloaded automatic from S3 to the hosts
AVALANCHED_BIN_PATH=/home/ubuntu/avalanche-ops/target/release/avalanched-aws
AWS_VOLUME_PROVISIONER_BIN_PATH=/tmp/aws-volume-provisioner-new
AWS_IP_PROVISIONER_BIN_PATH=/tmp/aws-ip-provisioner-new
AVALANCHE_TELEMETRY_CLOUDWATCH_BIN_PATH=/tmp/avalanche-telemetry-cloudwatch
AVALANCHE_CONFIG_BIN_PATH=/home/ubuntu/avalanche-ops/target/release/avalanche-config
AVALANCHE_BIN_PATH=/home/ubuntu/go/src/github.com/ava-labs/avalanchego/build/avalanchego
AVALANCHE_PLUGIN_DIR_PATH=/home/ubuntu/go/src/github.com/ava-labs/avalanchego/build/plugin

cd /home/ubuntu/avalanche-ops
avalancheup-aws default-spec \
--region ap-northeast-2 \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-aws-volume-provisioner-local-bin ${AWS_VOLUME_PROVISIONER_BIN_PATH} \
--upload-artifacts-aws-ip-provisioner-local-bin ${AWS_IP_PROVISIONER_BIN_PATH} \
--upload-artifacts-avalanche-telemetry-cloudwatch-local-bin ${AVALANCHE_TELEMETRY_CLOUDWATCH_BIN_PATH} \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGIN_DIR_PATH} \
--instance-mode=on-demand \
--ip-mode=elastic \
--network-name custom \
--keys-to-generate 50 \
--keys-to-generate-type hot \
--subnet-evms 1
```
