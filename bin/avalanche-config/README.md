
## Avalanche configuration tool (`avalanche-config`)

**Only works with the fields that are defined in `avalanche_types::avalanchego::config`.**

```bash
./scripts/build.release.sh
./target/release/avalanche-config --help

./target/release/avalanche-config default --help
./target/release/avalanche-config add-whitelist-subnet --help

./target/release/avalanche-config default --network-name=mainnet
# ...
# Saved configuration to '/var/folders/jp/0bxslj2n0hbg2dx1ypk_y6j40000gn/T/9k5DPbXeuD.json'

./target/release/avalanche-config add-whitelist-subnet \
--original-config-file-path /var/folders/jp/0bxslj2n0hbg2dx1ypk_y6j40000gn/T/9k5DPbXeuD.json \
--new-config-file-path /tmp/new-whitelisted-subnet.json \
--subnet-id hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf
```
