
# Example

```bash
cargo build \
--release \
--bin devnet-faucet
```

```bash
cat > /tmp/devnet-faucet.keys <<EOF
- key: 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027
EOF
cat /tmp/devnet-faucet.keys
```

```bash
./target/release/devnet-faucet \
--log-level=info \
--http-host=127.0.0.1:3031 \
--chain-rpc-urls=http://localhost:9650/ext/bc/C/rpc \
--keys-file /tmp/devnet-faucet.keys
```

```bash
curl http://localhost:9650/ext/bc/C/rpc \
  -X POST \
  -H "Content-Type: application/json" \
  --data '{"method":"eth_chainId","params":[],"id":1,"jsonrpc":"2.0"}'
```

```bash
cast --to-dec 0xa868
# 43112
```
