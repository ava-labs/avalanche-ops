
## Avalanche KMS tool (`avalanche-kms-signer-aws`)

```bash
./scripts/build.release.sh
./target/release/avalanche-kms-signer-aws --help

./target/release/avalanche-kms-signer-aws create --help
./target/release/avalanche-kms-signer-aws delete --help
./target/release/avalanche-kms-signer-aws info --help
```

To create a new KMS CMK:

```bash
./target/release/avalanche-kms-signer-aws create \
--region=us-west-2
```

```yaml
# loaded CMK

id: arn:aws:kms:us-west-2:931867039610:key/95a4aec8-73ef-41f5-8a17-ed8ce3802677
key_type: aws-kms
addresses:
  1:
    x_address: X-avax10v45f4lrp9ch85z89nsure7nrszf82zk38usnp
    p_address: P-avax10v45f4lrp9ch85z89nsure7nrszf82zk38usnp
    c_address: C-avax10v45f4lrp9ch85z89nsure7nrszf82zk38usnp
short_address: CEFwyPzMVbNQDJe6qRNw5YBfr619AN67N
eth_address: 0xBD7fC504D23e5BB7C2FF9DdD6F30a1837BC3cd45

# (mainnet)
```

To get the key information:

```bash
# new CMK is successfully created
./target/release/avalanche-kms-signer-aws info \
--region=us-west-2 \
--network-id=1 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/95a4aec8-73ef-41f5-8a17-ed8ce3802677

./target/release/avalanche-kms-signer-aws info \
--region=us-west-2 \
--network-id=5 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/95a4aec8-73ef-41f5-8a17-ed8ce3802677

./target/release/avalanche-kms-signer-aws info \
--region=us-west-2 \
--network-id=1000 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/95a4aec8-73ef-41f5-8a17-ed8ce3802677
```

```yaml
# loaded CMK

id: arn:aws:kms:us-west-2:931867039610:key/95a4aec8-73ef-41f5-8a17-ed8ce3802677
key_type: aws-kms
addresses:
  1000:
    x_address: X-custom10v45f4lrp9ch85z89nsure7nrszf82zkzaw255
    p_address: P-custom10v45f4lrp9ch85z89nsure7nrszf82zkzaw255
    c_address: C-custom10v45f4lrp9ch85z89nsure7nrszf82zkzaw255
short_address: CEFwyPzMVbNQDJe6qRNw5YBfr619AN67N
eth_address: 0xBD7fC504D23e5BB7C2FF9DdD6F30a1837BC3cd45

# (network Id 1000)
```

To schedule the key deletion:

```bash
./target/release/avalanche-kms-signer-aws delete \
--region=us-west-2 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/95a4aec8-73ef-41f5-8a17-ed8ce3802677 \
--pending-windows-in-days 7
```
