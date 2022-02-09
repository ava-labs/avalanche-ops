
<br>

![Github Actions](https://github.com/gyuho/avalanche-ops/actions/workflows/build-test-release.yml/badge.svg) ![Github Actions](https://github.com/gyuho/avalanche-ops/actions/workflows/static-analysis.yml/badge.svg)

## Avalanche Ops

`avalanche-ops` is an operation toolkit for Avalanche nodes:
- 🦀 Written in Rust
- 🏗️ Fully automates VM (or physical machine) provisioning
- 🍏 Fully automates node installation
- 🚜 Fully automates node operations
- 💻 Fully automates test network setups

`avalanche-ops` is:
- 🚫 NOT a replacement of [`avalanchego`](https://github.com/ava-labs/avalanchego)
- 🚫 NOT implementing any client-side load generation (to be done in Avalanche client/node projects)
- 🚫 NOT implementing any Avalanche-specific test cases (focus on infrastructure setups)
- 🚫 NOT using Kubernetes, prefers physical machines (or cloud VMs)
- 🚫 **NOT production ready** (under heavy development, only used for testing)

### Installation

```bash
# to build manually
./scripts/build.release.sh

# TODO: not working
# ./scripts/build.cross.sh
```

```bash
# to download from the github release page
# https://github.com/ava-labs/avalanche-ops/releases/tag/tip
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/tip/avalanched-aws.x86_64-unknown-linux-gnu \
-o /tmp/avalanched-aws.x86_64-unknown-linux-gnu
```

It requires Avalanche node software to bootstrap the remote machines:

```bash
# https://github.com/ava-labs/avalanchego/releases
VERSION=1.7.5
DOWNLOAD_URL=https://github.com/ava-labs/avalanchego/releases/download/
rm -rf /tmp/avalanchego.tar.gz /tmp/avalanchego-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/avalanchego-linux-amd64-v${VERSION}.tar.gz -o /tmp/avalanchego.tar.gz
tar xzvf /tmp/avalanchego.tar.gz -C /tmp
find /tmp/avalanchego-v${VERSION}
```

### `avalanche-ops` on AWS

A single command to create a new Avalanche node from scratch and join any network of choice (e.g., test, fuji, main) or a custom Avalanche network with multiple nodes. Provisions all AWS resources required to run a node or network with recommended setups (configurable):

```bash
# "1337" here is the custom network ID
# must be matched with the one in genesis file
avalanche-ops-nodes-aws default-config \
--network-id 1337 \
--genesis-file artifacts/sample.genesis.json \
--avalanched-bin /tmp/avalanched-aws.x86_64-unknown-linux-gnu \
--avalanchego-bin /tmp/avalanchego-v1.7.4/avalanchego \
--plugins-dir /tmp/avalanchego-v1.7.4/plugins \
--config /tmp/test.yaml
```

```bash
# make sure you have access to your AWS account
ROLE_ARN=$(aws sts get-caller-identity --query Arn --output text);
echo $ROLE_ARN

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text);
echo ${ACCOUNT_ID}
```

```bash
# edit "/tmp/test.yaml" if needed
# to create resources
avalanche-ops-nodes-aws apply --config /tmp/test.yaml
```

```bash
# to clean up resources
# specify "--delete-all" to delete auto-created S3 bucket
# otherwise, S3 bucket is not deleted
avalanche-ops-nodes-aws delete --config /tmp/test.yaml
```

Avalanche node daemon that provisions and manages the software on the remote machine (e.g., generate certs, encrypt, upload to S3):

```bash
avalanched-aws
```

### Roadmap

- Failure injection testing
- Stress testing
- Log collection
- Metrics collection
- Support ARM
- Raspberry Pi
- Support key rotation

### Other projects

- [`avalanche-network-runner`](https://github.com/ava-labs/avalanche-network-runner) to run a local network (with Kubernetes)
- [`avalanchego-operator`](https://github.com/ava-labs/avalanchego-operator) to run a Kubernetes operator
