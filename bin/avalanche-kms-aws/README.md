
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
# created CMK signer (info for mainnet: ...
```

To get the key information:

```bash
# new CMK is successfully created
./target/release/avalanche-kms-aws info \
--region=us-west-2 \
--network-id=1 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/c014ac7d-8127-457c-bb07-e03999cb0112

./target/release/avalanche-kms-aws info \
--region=us-west-2 \
--network-id=5 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/c014ac7d-8127-457c-bb07-e03999cb0112

./target/release/avalanche-kms-aws info \
--region=us-west-2 \
--network-id=1000 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/c014ac7d-8127-457c-bb07-e03999cb0112
```

```yaml
id: arn:aws:kms:us-west-2:931867039610:key/c014ac7d-8127-457c-bb07-e03999cb0112
key_type: aws-kms
addresses:
  1000:
    x_address: X-custom1f65j6remlfmg890cvk4u655mx5697cfs7a0dj8
    p_address: P-custom1f65j6remlfmg890cvk4u655mx5697cfs7a0dj8
    c_address: C-custom1f65j6remlfmg890cvk4u655mx5697cfs7a0dj8
    short_address: 8AvNX4UvUe81bEkaCuzavXeAM7FXAhBb9
    eth_address: 0xfBEBeFcEB765ca806A5E3BfF22307eEEc7F1Db49
```

To schedule the key deletion:

```bash
./target/release/avalanche-kms-aws delete \
--region=us-west-2 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/c014ac7d-8127-457c-bb07-e03999cb0112 \
--pending-windows-in-days 7
```
