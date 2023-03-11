
## Avalanche configuration tool (`avalanche-config`)

**Only works with the fields that are defined in `avalanche_types::avalanchego::config`.**

```bash
./scripts/build.release.sh
./target/release/avalanche-config --help

./target/release/avalanche-config default --help
./target/release/avalanche-config add-track-subnet --help
```

To write some default configuration file:

```bash
./target/release/avalanche-config default \
--network-name=mainnet \
--config-file-path=/tmp/test.config.json
# ...
# Saved configuration to '/tmp/test.config.json'

cat /tmp/test.config.json
```

To write some default subnet configuration:

```bash
./target/release/avalanche-config subnet-config \
--proposer-min-block-delay 1000000000 \
--file-path /tmp/subnet-config.json

cat /tmp/subnet-config.json
```

To write some default subnet-evm chain configuration:

```bash
./target/release/avalanche-config subnet-evm chain-config \
--file-path /tmp/subnet-evm.chain-config.json
```

To write some default subnet-evm genesis:

```bash
./target/release/avalanche-config subnet-evm genesis \
--seed-eth-addresses 0x75E3DC1926Ca033Ee06B0C378B0079241921e2AA,0x557FDFCAEff5daDF7287344f4E30172e56EC7aec \
--file-path /tmp/subnet-evm.genesis.json
```

To add new tracked subnets:

```bash
# new subnet id is successfully added
./target/release/avalanche-config add-track-subnet \
--skip-prompt \
--config-file-path /tmp/test.config.json \
--subnet-id hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf
# ... "tracked-subnets":"hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf" ...

cat /tmp/test.config.json

# duplicate subnet id is ignored
./target/release/avalanche-config add-track-subnet \
--skip-prompt \
--config-file-path /tmp/test.config.json \
--subnet-id hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf
# ... "tracked-subnets":"hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf" ...

cat /tmp/test.config.json

# new subnet id is successfully added
./target/release/avalanche-config add-track-subnet \
--skip-prompt \
--config-file-path /tmp/test.config.json \
--subnet-id 2ybKHWNFLh8kpWQwCpuaQLdinTLRTt6s6nkbr14gnrtjk5YMr
# ... "tracked-subnets":"2ybKHWNFLh8kpWQwCpuaQLdinTLRTt6s6nkbr14gnrtjk5YMr,hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf" ...

cat /tmp/test.config.json
```
