use std::collections::HashMap;

use lazy_static::lazy_static;

pub const VERSION: u16 = 0;

lazy_static! {
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/codec#Registry
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/wallet/chain/x/codec.go#L31
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/avm/codec_registry.go
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/codec/reflectcodec/type_codec.go#L128-L131
    ///     (used for encoding Go interface type into a "struct")
    pub static ref X_TYPES: HashMap< &'static str, usize> = {
        let mut m = HashMap::new();
        m.insert("avm.BaseTx", 0);
        m.insert("avm.CreateAssetTx", 1);
        m.insert("avm.OperationTx", 2);
        m.insert("avm.ImportTx", 3);
        m.insert("avm.ExportTx", 4);
        m.insert("secp256k1fx.TransferInput", 5);
        m.insert("secp256k1fx.MintOutput", 6);
        m.insert("secp256k1fx.TransferOutput", 7);
        m.insert("secp256k1fx.MintOperation", 8);
        m.insert("secp256k1fx.Credential", 9);
        m.insert("nftfx.MintOutput", 10);
        m.insert("nftfx.TransferOutput", 11);
        m.insert("nftfx.MintOperation", 12);
        m.insert("nftfx.TransferOperation", 13);
        m.insert("nftfx.Credential", 14);
        m.insert("propertyfx.MintOutput", 15);
        m.insert("propertyfx.OwnedOutput", 16);
        m.insert("propertyfx.MintOperation", 17);
        m.insert("propertyfx.BurnOperation", 18);
        m.insert("propertyfx.Credential", 19);
        m
    };

    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/codec.go
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/codec/reflectcodec/type_codec.go#L128-L131
    ///     (used for encoding Go interface type into a "struct")
    pub static ref P_TYPES: HashMap< &'static str, usize> = {
        let mut m = HashMap::new();
        m.insert("platformvm.ProposalBlock", 0);
        m.insert("platformvm.AbortBlock", 1);
        m.insert("platformvm.CommitBlock", 2);
        m.insert("platformvm.StandardBlock", 3);
        m.insert("platformvm.AtomicBlock", 4);
        m.insert("secp256k1fx.TransferInput", 5);
        m.insert("secp256k1fx.MintOutput", 6);
        m.insert("secp256k1fx.TransferOutput", 7);
        m.insert("secp256k1fx.MintOperation", 8);
        m.insert("secp256k1fx.Credential", 9);
        m.insert("secp256k1fx.Input", 10);
        m.insert("secp256k1fx.OutputOwners", 11);
        m.insert("platformvm.UnsignedAddValidatorTx", 12);
        m.insert("platformvm.UnsignedAddSubnetValidatorTx", 13);
        m.insert("platformvm.UnsignedAddDelegatorTx", 14);
        m.insert("platformvm.UnsignedCreateChainTx", 15);
        m.insert("platformvm.UnsignedCreateSubnetTx", 16);
        m.insert("platformvm.UnsignedImportTx", 17);
        m.insert("platformvm.UnsignedExportTx", 18);
        m.insert("platformvm.UnsignedAdvanceTimeTx", 19);
        m.insert("platformvm.UnsignedRewardValidatorTx", 20);
        m.insert("platformvm.StakeableLockIn", 21);
        m.insert("platformvm.StakeableLockOut", 22);
        m
    };
}
