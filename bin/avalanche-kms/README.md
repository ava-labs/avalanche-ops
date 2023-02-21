
## Avalanche KMS tool (`avalanche-kms`)

```bash
./scripts/build.release.sh
./target/release/avalanche-kms --help

./target/release/avalanche-kms create --help
./target/release/avalanche-kms delete --help
./target/release/avalanche-kms info --help
```

To create a new KMS CMK:

```bash
./target/release/avalanche-kms create \
--region=us-west-2
```

```yaml
# loaded CMK

id: arn:aws:kms:us-west-2:931867039610:key/9ca6d1a5-bc21-4326-8562-ad106f36a439
key_type: aws-kms
addresses:
  1:
    x: X-avax1e2hc8l88ew0y8muscv3e9u5ufumqnmzj8vnvfd
    p: P-avax1e2hc8l88ew0y8muscv3e9u5ufumqnmzj8vnvfd
short_address: KUhknai5F6Hsr7SR7N1RjGidfCVSi6Umg
eth_address: 0x75E3DC1926Ca033Ee06B0C378B0079241921e2AA
h160_address: 0x75e3dc1926ca033ee06b0c378b0079241921e2aa

# (mainnet)
```

To get the key information:

```bash
# new CMK is successfully created
./target/release/avalanche-kms info \
--region=us-west-2 \
--network-id=1 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/9ca6d1a5-bc21-4326-8562-ad106f36a439

./target/release/avalanche-kms info \
--region=us-west-2 \
--network-id=5 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/9ca6d1a5-bc21-4326-8562-ad106f36a439

./target/release/avalanche-kms info \
--region=us-west-2 \
--network-id=1000 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/9ca6d1a5-bc21-4326-8562-ad106f36a439
```

```yaml
# loaded CMK

id: arn:aws:kms:us-west-2:931867039610:key/9ca6d1a5-bc21-4326-8562-ad106f36a439
key_type: aws-kms
addresses:
  1000:
    x: X-custom1e2hc8l88ew0y8muscv3e9u5ufumqnmzj5kpkwc
    p: P-custom1e2hc8l88ew0y8muscv3e9u5ufumqnmzj5kpkwc
short_address: KUhknai5F6Hsr7SR7N1RjGidfCVSi6Umg
eth_address: 0x75E3DC1926Ca033Ee06B0C378B0079241921e2AA
h160_address: 0x75e3dc1926ca033ee06b0c378b0079241921e2aa

# (network Id 1000)
```

To schedule the key deletion:

```bash
./target/release/avalanche-kms delete \
--region=us-west-2 \
--key-arn arn:aws:kms:us-west-2:931867039610:key/9ca6d1a5-bc21-4326-8562-ad106f36a439 \
--pending-windows-in-days 7
```
