
<br>

![Github Actions](https://github.com/ava-labs/avalanche-ops/actions/workflows/test-and-release.yml/badge.svg)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

See https://talks.gyuho.dev/avalanche-aws-2022q3.html for slides.

See ["Cheapest way to set up a network or validator"](avalancheup-aws/recipes-aws.md#cheapest-way-to-set-up-a-network-or-validator).

[![asciicast](https://asciinema.org/a/oHrRU83Zfd6hApexUknm8QphG.svg)](https://asciinema.org/a/oHrRU83Zfd6hApexUknm8QphG)

# Avalanche Ops

A **single command to launch Avalanche nodes from scratch that joins any network of choice (e.g., test, fuji, main) or create a custom Avalanche network**. Provisions all resources required to run a node or network with recommended setups (configurable).

Distributed systems are full of subtle edge cases. The fact that such event or bug may only emerge under special circumstances warrants exhaustive test coverage beyond simple unit testing. Furthermore, the lack of tests slows down software release process, let alone long-term architectural changes.

`avalanche-ops` aims to find vulnerabilities in Avalanche protocol by intentionally causing failures, and provides a reliable and faster way to validate the ﬁx. In addition, `avalanche-ops` implements some basic principles and best practices for operating Avalanche node in production.

`avalanche-ops` is a set of operation toolkits for Avalanche nodes:
- 🦀 Written in Rust
- ✅ Optimized for ephemeral network create/delete
- ✅ Fully automates VM (or physical machine) provisioning
- ✅ Fully automates node installation and operations
- ✅ Fully automates custom network setups
- ✅ Fully automates custom VM (subnet) setups
- 🔥 Simulates routine failure conditions (slow network)
- 📨 Securely encrypt all artifacts in case of backups
- Automates subnet/VM installation
- Automates load/stress testing
- Support private network

`avalanche-ops` is:
- 🚫 NOT a replacement of [`avalanchego`](https://github.com/ava-labs/avalanchego)
- 🚫 NOT implementing any client-side load generation (to be done in Avalanche client/node projects)
- 🚫 NOT implementing any Avalanche-specific test cases (focus on infrastructure setups)
- 🚫 NOT using Kubernetes, prefers physical machines (or cloud VMs)
- 🚫 **NOT production ready yet** (under heavy development)

## Workflow

**`avalancheup`** is the client (or "control plane") that runs on the operator's host machine or test runner, which provisions a set of remote machines based on user-provided configuration. **`avalanched`** is an agent (or daemon) that runs on every remote machine, which creates and installs Avalanche-specific resources (e.g., TLS certificate generation, anchor-node discovery, write avalanche node service file).

To set up a custom network, provide **`avalancheup`** with executable binaries to run in remote machines. Which then generates a genesis file with pre-funded keys and provisions remote machines to install the user-provided artifacts. A custom network requires two groups of machines: (1) anchor node (beacon node, only required for custom network), and (2) non-anchor node. During the bootstrap phase, regardless of its node kind, **`avalanched`** auto-generates TLS certificates and stores them encrypted in the remote storage. Beacon nodes publish its information in YAML to the shared remote storage, and non-anchor nodes list the storage to discover anchor nodes.

![avalanche-ops.drawio.png](./avalancheup-aws/img/avalancheup.drawio.png)

## `avalancheup` and `avalanched` on AWS

See [`recipes-aws.md`](./avalancheup-aws/recipes-aws.md) and [`example-aws.md`](./avalancheup-aws/example-aws.md).

![example-aws/32](./avalancheup-aws/img/example-aws/32.png)

![example-aws/43](./avalancheup-aws/img/example-aws/43.png)

## Installation

```bash
# to build manually
./scripts/build.release.sh
```

```bash
# to download from the github release page
# https://github.com/ava-labs/avalanche-ops/releases/tag/latest
# or visit https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
```

## TODOs

Contributions are welcome!

- Support mainnet fork
- Failure injection testing
- Better Avalanche node health checks
- Support ARM
- Support Raspberry Pi
- Support key rotation

## Other projects

- [`avalanche-network-runner`](https://github.com/ava-labs/avalanche-network-runner) to run a local network
- [`avalanchego-operator`](https://github.com/ava-labs/avalanchego-operator) to run a Kubernetes operator
