
To write some default subnet configuration:

```bash
./target/release/avalancheup-aws subnet-config \
--proposer-min-block-delay 1000000000 \
--file-path /tmp/subnet-config.json

cat /tmp/subnet-config.json
```

To write some default subnet-evm chain configuration:

```bash
./target/release/avalancheup-aws subnet-evm chain-config \
--file-path /tmp/subnet-evm.chain-config.json
```

To write some default subnet-evm genesis:

```bash
./target/release/avalancheup-aws subnet-evm genesis \
--seed-eth-addresses 0x75E3DC1926Ca033Ee06B0C378B0079241921e2AA,0x557FDFCAEff5daDF7287344f4E30172e56EC7aec \
--file-path /tmp/subnet-evm.genesis.json
```
