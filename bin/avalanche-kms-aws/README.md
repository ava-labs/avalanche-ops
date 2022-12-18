
## Avalanche KMS tool (`avalanche-kms-aws`)

```bash
./scripts/build.release.sh
./target/release/avalanche-kms-aws --help

./target/release/avalanche-kms-aws create --help
./target/release/avalanche-kms-aws delete --help
./target/release/avalanche-kms-aws info --help
```

To create a new KMS CMK:

```bash
./target/release/avalanche-kms-aws create \
--region=us-west-2
# ...
# Saved configuration to '/tmp/test.config.json'
```

To get the key information:

```bash
# new CMK is successfully created
./target/release/avalanche-kms-aws info \
--region=us-west-2 \
--network-id=1 \
--key-arn ...
# 

./target/release/avalanche-kms-aws info \
--region=us-west-2 \
--network-id=5 \
--key-arn ...
# 

./target/release/avalanche-kms-aws info \
--region=us-west-2 \
--network-id=1000 \
--key-arn ...
# 
```

To schedule the key deletion:

```bash
./target/release/avalanche-kms-aws delete \
--region=us-west-2 \
--key-arn ... \
--pending-windows-in-days 7
# 
```
