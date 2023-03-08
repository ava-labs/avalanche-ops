
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
