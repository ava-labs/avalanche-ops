use std::collections::HashMap;

use lazy_static::lazy_static;

pub const VERSION: u16 = 0;

lazy_static! {
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/codec#Registry
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/wallet/chain/x/codec.go#L31
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/avm/codec_registry.go
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/codec/reflectcodec/type_codec.go#L128-L131
    ///     (used for encoding Go interface type into a "struct")
    pub static ref X_TYPES: HashMap<String, usize> = {
        let mut m = HashMap::new();
        m.insert("avm.BaseTx".to_string(), 0);
        m.insert("avm.CreateAssetTx".to_string(), 1);
        m.insert("avm.OperationTx".to_string(), 2);
        m.insert("avm.ImportTx".to_string(), 3);
        m.insert("avm.ExportTx".to_string(), 4);
        m.insert("secp256k1fx.TransferInput".to_string(), 5);
        m.insert("secp256k1fx.MintOutput".to_string(), 6);
        m.insert("secp256k1fx.TransferOutput".to_string(), 7);
        m.insert("secp256k1fx.MintOperation".to_string(), 8);
        m.insert("secp256k1fx.Credential".to_string(), 9);
        m.insert("nftfx.MintOutput".to_string(), 10);
        m.insert("nftfx.TransferOutput".to_string(), 11);
        m.insert("nftfx.MintOperation".to_string(), 12);
        m.insert("nftfx.TransferOperation".to_string(), 13);
        m.insert("nftfx.Credential".to_string(), 14);
        m.insert("propertyfx.MintOutput".to_string(), 15);
        m.insert("propertyfx.OwnedOutput".to_string(), 16);
        m.insert("propertyfx.MintOperation".to_string(), 17);
        m.insert("propertyfx.BurnOperation".to_string(), 18);
        m.insert("propertyfx.Credential".to_string(), 19);
        m
    };

    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/codec.go
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/codec/reflectcodec/type_codec.go#L128-L131
    ///     (used for encoding Go interface type into a "struct")
    pub static ref P_TYPES: HashMap<String, usize> = {
        let mut m = HashMap::new();
        m.insert("platformvm.ProposalBlock".to_string(), 0);
        m.insert("platformvm.AbortBlock".to_string(), 1);
        m.insert("platformvm.CommitBlock".to_string(), 2);
        m.insert("platformvm.StandardBlock".to_string(), 3);
        m.insert("platformvm.AtomicBlock".to_string(), 4);
        m.insert("secp256k1fx.TransferInput".to_string(), 5);
        m.insert("secp256k1fx.MintOutput".to_string(), 6);
        m.insert("secp256k1fx.TransferOutput".to_string(), 7);
        m.insert("secp256k1fx.MintOperation".to_string(), 8);
        m.insert("secp256k1fx.Credential".to_string(), 9);
        m.insert("secp256k1fx.Input".to_string(), 10);
        m.insert("secp256k1fx.OutputOwners".to_string(), 11);
        m.insert("platformvm.UnsignedAddValidatorTx".to_string(), 12);
        m.insert("platformvm.UnsignedAddSubnetValidatorTx".to_string(), 13);
        m.insert("platformvm.UnsignedAddDelegatorTx".to_string(), 14);
        m.insert("platformvm.UnsignedCreateChainTx".to_string(), 15);
        m.insert("platformvm.UnsignedCreateSubnetTx".to_string(), 16);
        m.insert("platformvm.UnsignedImportTx".to_string(), 17);
        m.insert("platformvm.UnsignedExportTx".to_string(), 18);
        m.insert("platformvm.UnsignedAdvanceTimeTx".to_string(), 19);
        m.insert("platformvm.UnsignedRewardValidatorTx".to_string(), 20);
        m.insert("platformvm.StakeableLockIn".to_string(), 21);
        m.insert("platformvm.StakeableLockOut".to_string(), 22);
        m
    };
}
