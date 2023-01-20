
## Avalanche configuration tool (`avalanche-config`)

**Only works with the fields that are defined in `avalanche_types::avalanchego::config`.**

```bash
./scripts/build.release.sh
./target/release/avalanche-config --help

./target/release/avalanche-config default --help
./target/release/avalanche-config add-tracked-subnet --help
```

To write some default configuration file:

```bash
./target/release/avalanche-config default \
--network-name=mainnet \
--config-file-path=/tmp/test.config.json
# ...
# Saved configuration to '/tmp/test.config.json'
```

To add new tracked subnets:

```bash
# new subnet id is successfully added
./target/release/avalanche-config add-tracked-subnet \
--skip-prompt \
--original-config-file-path /tmp/test.config.json \
--new-config-file-path /tmp/test.config.2.json \
--subnet-id hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf
# ... "tracked-subnets":"hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf" ...

# duplicate subnet id is ignored
./target/release/avalanche-config add-tracked-subnet \
--skip-prompt \
--original-config-file-path /tmp/test.config.2.json \
--new-config-file-path /tmp/test.config.3.json \
--subnet-id hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf
# ... "tracked-subnets":"hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf" ...

# new subnet id is successfully added
./target/release/avalanche-config add-tracked-subnet \
--skip-prompt \
--original-config-file-path /tmp/test.config.3.json \
--new-config-file-path /tmp/test.config.3.json \
--subnet-id 2ybKHWNFLh8kpWQwCpuaQLdinTLRTt6s6nkbr14gnrtjk5YMr
# ... "tracked-subnets":"2ybKHWNFLh8kpWQwCpuaQLdinTLRTt6s6nkbr14gnrtjk5YMr,hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf" ...
```
