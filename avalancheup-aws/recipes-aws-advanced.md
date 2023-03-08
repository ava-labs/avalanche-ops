
# avalanche-ops-recipes

Recipes for avalanche-ops https://github.com/ava-labs/avalanche-ops.

## Step 1: Install `avalancheup`

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

Make sure you have access to the following CLI:

```bash
avalancheup-aws -h
```

## Step 2: Install artifacts on your local machine

In order to provision avalanche node, you need the software compiled for the remote machine's OS and architecture (e.g., if your server runs linux, then you need provide linux binaries to `avalancheup` commands).

For instance, to download the latest `avalanchego` release:

```bash
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
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
--upload-artifacts-avalanched-local-bin ./avalanched-aws.x86_64-unknown-linux-gnu \
--upload-artifacts-avalanche-local-bin [AVALANCHE_BUILD_DIR]/avalanchego \
--upload-artifacts-plugin-local-dir [AVALANCHE_BUILD_DIR]/plugins \
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

### Updates

```bash
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o /tmp/avalanched-aws.x86_64-unknown-linux-gnu

chmod +x /tmp/avalanched-aws.x86_64-unknown-linux-gnu
/tmp/avalanched-aws.x86_64-unknown-linux-gnu --version





# update "avalanched"
# it runs "sudo systemctl stop avalanche.service" and "restart"
sudo systemctl stop avalanched.service
sudo systemctl disable avalanched.service

sudo mv /tmp/avalanched-aws.x86_64-unknown-linux-gnu /usr/local/bin/avalanched
/usr/local/bin/avalanched --version

sudo systemctl enable avalanched.service
sudo systemctl restart --no-block avalanched.service

sudo tail /var/log/avalanched.log
sudo tail -f /var/log/avalanched.log
```

```bash
curl -L \
https://github.com/ava-labs/avalanche-telemetry/releases/download/latest/avalanche-telemetry-cloudwatch.x86_64-unknown-linux-gnu \
-o /tmp/avalanche-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu

chmod +x /tmp/avalanche-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu
/tmp/avalanche-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu --version





# update "avalanche-telemetry-cloudwatch"
sudo systemctl stop avalanche-telemetry-cloudwatch.service
sudo systemctl disable avalanche-telemetry-cloudwatch.service

sudo mv /tmp/avalanche-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu /usr/local/bin/avalanche-telemetry-cloudwatch
/usr/local/bin/avalanche-telemetry-cloudwatch --version

sudo systemctl enable avalanche-telemetry-cloudwatch.service
sudo systemctl restart --no-block avalanche-telemetry-cloudwatch.service

sudo tail /var/log/avalanche-telemetry-cloudwatch.log
sudo tail -f /var/log/avalanche-telemetry-cloudwatch.log
```

```bash
# update "AVALANCHE_TELEMETRY_CLOUDWATCH_RULES_FILE_PATH" for rules
vi /data/avalanche-telemetry-cloudwatch.rules.yaml
```

```bash
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}

chmod +x /tmp/avalanchego-v${VERSION}/avalanchego
/tmp/avalanchego-v${VERSION}/avalanchego --version





# update "avalanchego"
sudo systemctl stop avalanche.service
sudo systemctl disable avalanche.service

sudo mv /tmp/avalanchego-v${VERSION}/avalanchego /usr/local/bin/avalanche
/usr/local/bin/avalanche --version

sudo systemctl enable avalanche.service
sudo systemctl restart --no-block avalanche.service

sudo tail /var/log/avalanche/avalanche.log
sudo tail -f /var/log/avalanche/avalanche.log
```

### Cheapest way to set up a network or validator

```bash
cd ${HOME}/avalanche-ops
./scripts/build.release.sh
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--volume-size-in-gb 300 \
--avalanchego-log-level INFO
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name fuji \
--instance-mode spot \
--volume-size-in-gb 400 \
--avalanchego-log-level INFO
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name mainnet \
--instance-mode spot \
--volume-size-in-gb 500 \
--avalanchego-log-level INFO
```

### Use static IP

Set `--ip-mode=elastic` to provision elastic IPs to be 1:1 mapped to a node ID via [`aws-ip-provisioners`](https://github.com/ava-labs/ip-manager):

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--ip-mode=elastic \
--volume-size-in-gb 300 \
--avalanchego-log-level INFO
```

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

##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level DEBUG









# to run with the latest binaries automatically downloaded
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--avalanchego-log-level DEBUG








# to set your own AAD tag
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--aad-tag my-tag \
--network-name custom \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with Coreth EVM config file

See https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config for more.

```bash
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--coreth-metrics-enabled \
--coreth-continuous-profiler-enabled \
--coreth-offline-pruning-enabled \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with new install artifacts (trigger updates)

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws events update-artifacts \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with HTTP TLS enabled only for NLB DNS

TODOs
- Set up ACM CNAME with your DNS service (for subdomains).
- Set up CNAME record to point to the NLB DNS.

```bash
# REPLACE THIS WITH YOURS
ACM_CERT_ARN=arn:aws:acm:...:...:certificate/...

##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--nlb-acm-certificate-arn $ACM_CERT_ARN \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

```bash
cat ${HOME}/test-custom-https-for-nlb.yaml \
| grep cloudformation_asg_nlb_dns_name
# Use "https://[NLB_DNS]:443" for web wallet
```

### Custom network with NO initial database state, with HTTP TLS enabled only for `avalanchego`

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level INFO \
--avalanchego-http-tls-enabled \
--spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with snow-machine

See https://pkg.go.dev/github.com/ava-labs/snow-machine for more.

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--upload-artifacts-snow-machine-file-path ${HOME}/coreth.json \
--network-name custom \
---keys-to-generate 5 \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
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
rm -rf ${HOME}/go/src/github.com/ava-labs/avalanchego/build
cd ${HOME}/go/src/github.com/ava-labs/avalanchego
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh

cd ${HOME}/go/src/github.com/ava-labs/subnet-evm
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh \
${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins/srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy
```

```bash
cd ${HOME}/go/src/github.com/ava-labs/subnet-cli
go install -v .
subnet-cli create VMID subnetevm
# srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy
```

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins





#####
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level INFO \
--subnet-evms 1

#####
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
rm -rf ${HOME}/subnet-evm-test-keys
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--instance-mode spot \
--network-name custom \
--avalanchego-log-level INFO \
--keys-to-generate 30 \
--key-files-dir ${HOME}/subnet-evm-test-keys \
--subnet-evms 1

#####
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
rm -rf ${HOME}/subnet-evm-test-keys
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--instance-mode spot \
--network-name custom \
--avalanchego-log-level INFO \
--keys-to-generate 30 \
--key-files-dir ${HOME}/subnet-evm-test-keys \
--subnet-evms 1

# e.g., adjust gas limit
# https://www.rapidtables.com/convert/number/hex-to-decimal.html
# 1000000
# 0xF4240

# this will print out the list of commands to create resources
```

```bash
# only if you want to delete s3 objects + cloudwatch logs + EIPs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--delete-elastic-ips \
--spec-file-path [YOUR_SPEC_PATH]
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

`apply` command will output the following. Use the following to get access to each EC2 instance:

```bash
chmod 400 /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key
# ...
```

```bash
# when "2S6hhvrG4yKsyNngETcph9Rfmvc6RvAemAwu4fPaYenndwLUs7" is the subnet ID from subnet-cli
sudo systemctl cat avalanche
/usr/local/bin/plugin/srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy --version

# to replace the avalanche configuration
sudo cat /data/avalanche-configs/config.json
cp /data/avalanche-configs/config.json /tmp/avalanche.config.json
sed -i -- 's/hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf/2S6hhvrG4yKsyNngETcph9Rfmvc6RvAemAwu4fPaYenndwLUs7/g' /tmp/avalanche.config.json
cat /tmp/avalanche.config.json
sudo cp /tmp/avalanche.config.json /data/avalanche-configs/config.json

sudo systemctl restart avalanche
sleep 5
sudo tail -200 /var/log/avalanche/avalanche.log | grep 2S6hhvrG4yKsyNngETcph9Rfmvc6RvAemAwu4fPaYenndwLUs7

# to check the status
sudo find /var/log/avalanche/
sudo tail /var/log/avalanche/avalanche.log
```

> 2022-08-17T12:00:04.041-0700	info	client/p.go:497	creating blockchain	{"subnetId": "2cGHaEMbdPUdTJQjKhaxi8TPYeFCmwBAW1iqzFzY3KvBU6b4xG", "chainName": "subnetevm", "vmId": "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy", "createBlockchainTxFee": 100000000}
created blockchain "55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1" (took 179.72724ms)

```bash
# when "55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1" is the blockchain ID
# for instance, the subnet-cli will return
# created blockchain "55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1" (took 179.72724ms)
cat [YOUR_SPEC_PATH] | grep metamask_rpc:

# use the blockchain ID for metamask RPC
# or use the public IP of the validator node
http://[PUBLIC-DNS]:9650/ext/bc/55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1/rpc

# check the logs
sudo tail /var/log/avalanche/55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1.log
```

### Fuji network with NO initial database state

This will sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name fuji \
--avalanchego-log-level INFO







# to download install artifacts on remote machines automatically
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name fuji \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name fuji \
--instance-mode spot \
--avalanchego-log-level INFO







cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Fuji network with NO initial database state, with "avalanched-aws" lite mode

This will sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

# download latest binary from github
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--avalanched-use-default-config \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--network-name fuji \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Fuji network with NO initial database state, with fast-sync

This will fast-sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name fuji \
--avalanchego-log-level INFO \
--avalanchego-state-sync-ids ... \
--avalanchego-state-sync-ips ... \
--spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Main network with NO initial database state

This will sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHE_CONFIG_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanche-config
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanche-config.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanche-config.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHE_CONFIG_BIN_PATH=${HOME}/avalanche-config.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
AVALANCHE_BIN_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/avalanchego
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_BIN_PATH=/tmp/avalanchego-v${VERSION}/avalanchego

##
# if compiled locally
AVALANCHE_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/ava-labs/avalanchego/build/plugins
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.9.7
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
VERSION=1.9.7
AVALANCHE_PLUGINS_DIR_PATH=/tmp/avalanchego-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanche-config-local-bin ${AVALANCHE_CONFIG_BIN_PATH} \
--upload-artifacts-avalanched-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanche-local-bin ${AVALANCHE_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${AVALANCHE_PLUGINS_DIR_PATH} \
--network-name mainnet \
--avalanchego-log-level INFO


cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name mainnet \
--instance-mode spot \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name mainnet \
--instance-mode spot \
--avalanchego-log-level INFO


cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
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
