/// TODO: support https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config in "chain_config_dir"
/// TODO: pre-allocate funds for generated keys

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#Genesis
/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/params#ChainConfig
/// ref. https://github.com/ava-labs/avalanchego/tree/dev/genesis
/// ref. https://github.com/ava-labs/avalanche-network-runner/blob/main/local/default/genesis.json
pub const DEFAULT_GENESIS: &str = r#"
{
    "config": {
        "chainId": 43112,
        "homesteadBlock": 0,
        "daoForkBlock": 0,
        "daoForkSupport": true,
        "eip150Block": 0,
        "eip150Hash": "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "apricotPhase1BlockTimestamp": 0,
        "apricotPhase2BlockTimestamp": 0
    },
    "nonce": "0x0",
    "timestamp": "0x0",
    "extraData": "0x00",
    "gasLimit": "0x5f5e100",
    "difficulty": "0x0",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
        "8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC": {
            "balance": "0x295BE96E64066972000000"
        }
    },
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
"#;
