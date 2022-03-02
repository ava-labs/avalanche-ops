/// TODO: support https://pkg.go.dev/github.com/ava-labs/subnet-evm/plugin/evm#Config in "chain_config_dir"
///
/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/core#Genesis
/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/params#ChainConfig
/// ref. https://github.com/ava-labs/subnet-evm/blob/master/scripts/run.sh
/// ref. https://github.com/ava-labs/avalanchego/tree/dev/genesis
/// ref. https://github.com/ava-labs/avalanche-network-runner/blob/main/local/default/genesis.json
pub const DEFAULT_GENESIS: &str = r#"
{
    "config": {
        "chainId": 99999,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip150Hash": "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "subnetEVMTimestamp": 0,
        "feeConfig": {
            "gasLimit": 20000000,
            "minBaseFee": 1000000000,
            "targetGas": 100000000,
            "baseFeeChangeDenominator": 48,
            "minBlockGasCost": 0,
            "maxBlockGasCost": 10000000,
            "targetBlockRate": 2,
            "blockGasCostStep": 500000
        }
    },
    "airdropHash": "0xccbf8e430b30d08b5b3342208781c40b373d1b5885c1903828f367230a2568da",
    "airdropAmount": "0x8AC7230489E80000",
    "alloc": {
        "D23cbfA7eA985213aD81223309f588A7E66A246A": {
            "balance": "0x52B7D2DCC80CD2E4000000"
        }
    },
    "nonce": "0x0",
    "timestamp": "0x0",
    "extraData": "0x00",
    "gasLimit": "0x1312D00",
    "difficulty": "0x0",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
"#;
