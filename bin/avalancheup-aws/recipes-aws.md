
*See [0.0.10 recipes](https://github.com/ava-labs/avalanche-ops/blob/v0.0.10/bin/avalancheup-aws/recipes-aws.md) for old commands.*

**UPDATED as of https://github.com/ava-labs/avalanche-ops/releases/tag/v0.1.0**

# avalanche-ops-recipes

Recipes for avalanche-ops https://github.com/ava-labs/avalanche-ops.

## Step 1: Install `avalancheup`

To download from release, visit https://github.com/ava-labs/avalanche-ops/releases.

To compiles from source:

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

Make sure you have access to the following CLI:

```bash
avalancheup-aws -h
```

## Step 2: Install artifacts on your local machine

In order to provision avalanche node, you need the software compiled for the remote machine's OS and architecture (e.g., if your server runs linux, then you need provide linux binaries to `avalancheup` commands).

For instance, to download the latest `avalanchego` release:

```bash
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.7.14
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
```

To cross-compile locally, run something like:

```bash
# https://github.com/FiloSottile/homebrew-musl-cross
brew install FiloSottile/musl-cross/musl-cross
ln -s /usr/local/opt/musl-cross/bin/x86_64-linux-musl-gcc /usr/local/bin/musl-gcc

# -ldflags=-w to turn off DWARF debugging information
# -ldflags=-s to disable generation of the Go symbol table
rm -rf ${HOME}/go/src/github.com/ava-labs/avalanchego/build
cd ${HOME}/go/src/github.com/ava-labs/avalanchego
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh

find ${HOME}/go/src/github.com/ava-labs/avalanchego/build
ls -lah ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
```

You also need the `avalanched` daemon to run in the remote machines, which can be downloaded from the release page https://github.com/ava-labs/avalanche-ops/releases.

```bash
# this does not work... manually download for now...
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
```

## Step 3: Write avalanche-ops spec file

Now you need to write specification of how networks/nodes are to be provisioned. Use `avalancheup-aws default-spec` to auto-generate the file with some defaults.

```bash
avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ./avalanched-aws.x86_64-unknown-linux-gnu \
--install-artifacts-avalanche-bin [AVALANCHE_BUILD_DIR]/avalanchego \
--install-artifacts-plugins-dir [AVALANCHE_BUILD_DIR]/plugins \
--network-name custom \
--avalanchego-log-level INFO \
--spec-file-path spec.yaml
```

## Step 4: Apply the spec

Apply the spec to create resources:

```bash
# make sure you have access to your AWS account
ROLE_ARN=$(aws sts get-caller-identity --query Arn --output text);
echo $ROLE_ARN

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text);
echo ${ACCOUNT_ID}
```

```bash
avalancheup-aws apply --spec-file-path spec.yaml
avalancheup-aws delete --spec-file-path spec.yaml
```

Once `apply` command succeeds, the terminal outputs some helper commands to access the instances:

```bash
chmod 400 test.key
# instance 'i-abc' (running, us-west-2a)
ssh -o "StrictHostKeyChecking no" -i test.key ubuntu@52.41.144.41
aws ssm start-session --region us-west-2 --target i-abc

# in the machine, you can run something like this
sudo tail -f /var/log/avalanched.log
sudo tail -f /var/log/avalanche/avalanche.log
ls -lah /data/

# logs are available in CloudWatch
# metrics are available in CloudWatch
```

## Step 5: Connect to MetaMask

```bash
# add custom network to MetaMask using the following chain ID and RPC
cat [YOUR_SPEC_PATH] | grep metamask_rpc:
cat [YOUR_SPEC_PATH] | grep chainId:

# use pre-funded test keys
cat [YOUR_SPEC_PATH] | grep private_key_hex:
```

## Step 6: Delete

Make sure to delete the resources if you don't need them anymore:

```bash
avalancheup-aws delete --spec-file-path spec.yaml

# add these if you don't need log groups
# --delete-cloudwatch-log-group \
# --delete-s3-objects
```

## Recipes

- If `avalancheup-aws default-spec --spec-file-path` is **non-empty**, test ID is set based on the file name.
- If `avalancheup-aws default-spec --spec-file-path` is **not specified (empty)**, test ID is auto-generated.

### Custom network with NO initial database state

```bash
rm -rf ${HOME}/go/src/github.com/ava-labs/avalanchego/build
cd ${HOME}/go/src/github.com/ava-labs/avalanchego
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh
```

```bash
# to set the test ID "my-test-cluster"
# use "--spec-file-path ~/my-test-cluster.yaml"

# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.7.14
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.7.14
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${AVALANCHE_BIN_PATH} \
--install-artifacts-plugins-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

```bash
# to check balances
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws check-balances \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with Coreth EVM config file

See https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config for more.

```bash
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.7.14
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.7.14
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${AVALANCHE_BIN_PATH} \
--install-artifacts-plugins-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--coreth-metrics-enabled \
--coreth-continuous-profiler-enabled \
--coreth-offline-pruning-enabled \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with new install artifacts (trigger updates)

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws events update-artifacts \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with HTTP TLS enabled only for NLB DNS

TODOs
- Set up ACM CNAME with your DNS service (for subdomains).
- Set up CNAME record to point to the NLB DNS.

```bash
# REPLACE THIS WITH YOURS
ACM_CERT_ARN=arn:aws:acm:...:...:certificate/...

# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--nlb-acm-certificate-arn $ACM_CERT_ARN \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

```bash
cat ${HOME}/test-custom-https-for-nlb.yaml \
| grep cloudformation_asg_nlb_dns_name
# Use "https://[NLB_DNS]:443" for web wallet
```

### Custom network with NO initial database state, with HTTP TLS enabled only for `avalanchego`

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name custom \
--avalanchego-log-level INFO \
--avalanchego-http-tls-enabled \
--spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with snow-machine

See https://pkg.go.dev/github.com/ava-labs/snow-machine for more.

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--install-artifacts-snow-machine-file-path ${HOME}/coreth.json \
--network-name custom \
---keys-to-generate 5 \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with initial database state

TODO: network forking

### Custom network with NO initial database state, with subnet-evm

First, make sure you have `subnet-evm` installed in your local machine (for uploads). 

Install the following:
- https://github.com/ava-labs/subnet-evm
- https://github.com/ava-labs/subnet-cli

See ["install `subnet-evm` in the custom network"](./example-aws.md#optional-install-subnet-evm-in-the-custom-network) for demo.

```bash
cd ${HOME}/go/src/github.com/ava-labs/subnet-cli
go install -v .
subnet-cli create VMID subnetevm
# srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy

cd ${HOME}/go/src/github.com/ava-labs/subnet-evm
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh \
${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins/srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy
```

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

# TODO: pre-generate subnet ID
# replace "hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf"
# with real subnet ID from subnet-cli wizard
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name custom \
--avalanchego-log-level INFO \
--avalanchego-whitelisted-subnets hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf \
--enable-subnet-evm

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws check-balances --spec-file-path [YOUR_SPEC_PATH]
```

```bash
# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]

# to keep s3 objects + cloudwatch logs
```

Once the custom network is created, run the following commands to get the test key, RPC endpoints, and node IDs:

```bash
# make sure to pick the second "private_key_hex" or later keys
# that has immediately unlocked P-chain balance
cat [YOUR_SPEC_PATH] | grep private_key_hex:

  private_key_hex: ...
    private_key_hex: mykeyinhex
    ...

cat <<EOF > /tmp/test.key
...
EOF
cat /tmp/test.key
```

```bash
# to get HTTP RPC endpoints
cat [YOUR_SPEC_PATH] | grep http_rpc:
```

```bash
# to node IDs
# cat [YOUR_SPEC_PATH] | grep node_id:

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws read-spec \
--spec-file-path [YOUR_SPEC_PATH] \
--node-ids
```

```bash
# this will spend 2,000 AVAX
# for custom networks, anchor nodes are already validate primary network
# so, only non-anchor nodes will be added as validators
subnet-cli add validator \
--enable-prompt \
--private-key-path=/tmp/test.key \
--public-uri=[HTTP_RPC] \
--node-ids="..." \
--stake-amount=2000000000000 \
--validate-reward-fee-percent=2

subnet-cli wizard \
--enable-prompt \
--public-uri=[HTTP_RPC] \
--private-key-path=/tmp/test.key \
--vm-genesis-path=.../aops-custom-202203-h35WM6.subnet-evm.genesis.json \
--vm-id=srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy \
--chain-name=subnetevm \
--node-ids="..."
```

`apply` command will output the following. Use the following to get access to each EC2 instance:

```bash
chmod 400 /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key
# instance 'i-05f6c2cc7e7d619fc' (running, us-west-2a)
ssh -o "StrictHostKeyChecking no" -i /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key ubuntu@18.236.145.200
aws ssm start-session --region us-west-2 --target i-05f6c2cc7e7d619fc
# instance 'i-081a2e02547a9b1fb' (running, us-west-2b)
ssh -o "StrictHostKeyChecking no" -i /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key ubuntu@34.221.104.130
aws ssm start-session --region us-west-2 --target i-081a2e02547a9b1fb

chmod 400 /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key
# instance 'i-0f738acc6c0ecdf1c' (running, us-west-2b)
ssh -o "StrictHostKeyChecking no" -i /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key ubuntu@52.37.128.232
aws ssm start-session --region us-west-2 --target i-0f738acc6c0ecdf1c
# instance 'i-073a5a49d0f92a111' (pending, us-west-2c)
ssh -o "StrictHostKeyChecking no" -i /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key ubuntu@34.221.58.58
aws ssm start-session --region us-west-2 --target i-073a5a49d0f92a111
```

```bash
# when "2S6hhvrG4yKsyNngETcph9Rfmvc6RvAemAwu4fPaYenndwLUs7" is the subnet ID from subnet-cli
sudo systemctl cat avalanche
/usr/local/bin/plugins/srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy --version

# to replace the avalanche configuration
sudo cat /etc/avalanche.config.json
cp /etc/avalanche.config.json /tmp/avalanche.config.json
sed -i -- 's/hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf/2S6hhvrG4yKsyNngETcph9Rfmvc6RvAemAwu4fPaYenndwLUs7/g' /tmp/avalanche.config.json
cat /tmp/avalanche.config.json
sudo cp /tmp/avalanche.config.json /etc/avalanche.config.json

sudo systemctl restart avalanche
sleep 5
sudo tail -200 /var/log/avalanche/avalanche.log | grep 2S6hhvrG4yKsyNngETcph9Rfmvc6RvAemAwu4fPaYenndwLUs7

# to check the status
sudo find /var/log/avalanche/
sudo tail -f /var/log/avalanche/avalanche.log

# when "tCgnabTBM7511ySaLqBQMdGtJF2VuG5Jidiu5ma2BDiV7nXp8" is the blockchain ID
cat [YOUR_SPEC_PATH] | grep metamask_rpc:

# use the blockchain ID for metamask RPC
# for example, use the public IP of the validator node
http://[PUBLIC_IP]:9650/ext/bc/tCgnabTBM7511ySaLqBQMdGtJF2VuG5Jidiu5ma2BDiV7nXp8/rpc
[HTTP_RPC]/ext/bc/tCgnabTBM7511ySaLqBQMdGtJF2VuG5Jidiu5ma2BDiV7nXp8/rpc

# check the logs
sudo tail -f /var/log/avalanche/tCgnabTBM7511ySaLqBQMdGtJF2VuG5Jidiu5ma2BDiV7nXp8.log
```

References
- https://github.com/ava-labs/subnet-evm#run-subnet-cli-wizard
- https://github.com/ava-labs/subnet-evm/blob/v0.1.1/scripts/run.sh
- https://github.com/ava-labs/subnet-evm/blob/v0.1.1/runner/main.go

TODOs
- Support native P-chain API calls from `avalancheup`.
  - Create subnet.
  - Add subnet validator.
  - Create blockchain.
- Support subnet ID creation.
- Support dynamic subnet whitelisting.

### Fuji network with NO initial database state

This will sync from peer (rather than downloading from S3):

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name fuji \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

### Fuji network with NO initial database state, with fast-sync

This will fast-sync from peer (rather than downloading from S3):

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name fuji \
--avalanchego-log-level INFO \
--avalanchego-state-sync-ids ... \
--avalanchego-state-sync-ips ... \
--spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

### Fuji network with initial database state

```bash
# list and sort by timestamp
# this takes >40-min to complete...
# TOOD: make this faster
aws s3 ls --recursive --human-readable s3://avalanche-db-daily/testnet | sort

# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--db-backup-s3-region us-east-1 \
--db-backup-s3-bucket avalanche-db-daily \
--db-backup-s3-key testnet-db-daily-02-26-2022-050001-tar.gz \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name fuji \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws read-spec \
--spec-file-path [YOUR_SPEC_PATH]
--instance-ids

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws read-spec \
--spec-file-path [YOUR_SPEC_PATH]
--public-ips

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws read-spec \
--spec-file-path [YOUR_SPEC_PATH]
--nlb-endpoint

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws read-spec \
--spec-file-path [YOUR_SPEC_PATH]
--http-endpoints

cat $HOME/test-fuji-from-backup-db.yaml \
| grep cloudformation_asg_nlb_dns_name
# Use "https://[NLB_DNS]:443" for web wallet
```

### Main network with NO initial database state

This will sync from peer (rather than downloading from S3):

```bash
# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name mainnet \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

### Main network with initial database state

```bash
# list and sort by timestamp
# this takes hours to complete...
# TOOD: make this faster
aws s3 ls --recursive --human-readable s3://avalanche-db-daily/mainnet | sort

# download from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--db-backup-s3-region us-east-1 \
--db-backup-s3-bucket avalanche-db-daily \
--db-backup-s3-key mainnet-db-daily-02-25-2022-050003-tar.gz \
--install-artifacts-avalanched-bin ${AVALANCHED_BIN_PATH} \
--install-artifacts-avalanche-bin ${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego \
--install-artifacts-plugins-dir ${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins \
--network-name mainnet \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]

# only if you want to delete s3 objects + cloudwatch logs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--spec-file-path [YOUR_SPEC_PATH]
```

## FAQ: What if I want to control the systemd serviec manually?

`avalancheup` can help you set up infrastructure, but you may want full control over avalanche nodes for some tweaks. You can disable all systemd services for `avalancheup` as follows:

```bash
sudo systemctl cat avalanched.service
sudo systemctl status avalanched.service
sudo systemctl stop avalanched.service
sudo systemctl disable avalanched.service
sudo journalctl -f -u avalanched.service
sudo journalctl -u avalanched.service --lines=10 --no-pager
sudo tail -f /var/log/avalanched.log

sudo systemctl cat avalanche.service
sudo systemctl status avalanche.service
sudo systemctl stop avalanche.service
sudo systemctl disable avalanche.service
sudo journalctl -f -u avalanche.service
sudo journalctl -u avalanche.service --lines=10 --no-pager
sudo tail -f /var/log/avalanche/avalanche.log
```
