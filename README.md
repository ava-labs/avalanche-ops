
<br>

![Github Actions](https://github.com/gyuho/avalanche-ops/actions/workflows/build-test-release.yml/badge.svg) ![Github Actions](https://github.com/gyuho/avalanche-ops/actions/workflows/static-analysis.yml/badge.svg)

## Avalanche Ops

`avalanche-ops` is an operation toolkit for Avalanche nodes:
- Written in Rust
- Fully automates VM provisioning on cloud with recommended settings
- Fully automates node installation
- Fully automates test network setups

`avalanche-ops` is:
- Not a replacement of [`avalanchego`](https://github.com/ava-labs/avalanchego)
- Not implementing any client-side load generation (to be done in Avalanche client/node projects)
- Not implementing any Avalanche-specific test cases (instead focus on infrastructure setups)
- Not using Kubernetes, prefers physical machines (or cloud VMs)
- **Not production ready** (under heavy development, only used for testing)

### Installation

```bash
TBD
```

### `avalanche-ops-nodes-aws`

A single command to create a new Avalanche node from scratch and join any network of choice (e.g., test, fuji, main) or a custom Avalanche network with multiple nodes. Provisions all AWS resources required to run a node or network with recommended setups (configurable):

```bash
avalanche-ops-nodes-aws create
```

### `avalanched-aws`

Avalanche node daemon that provisions and manages the software on the remote machine (e.g., generate certs, encrypt, upload to S3):

```bash
avalanched-aws
```

### Roadmap

- Failure injection testing
- Log collection
- Metrics collection
- Raspberry Pi

### Other projects

- [`avalanche-network-runner`](https://github.com/ava-labs/avalanche-network-runner) to run a local network (with Kubernetes)
- [`avalanchego-operator`](https://github.com/ava-labs/avalanchego-operator) to run a Kubernetes operator

