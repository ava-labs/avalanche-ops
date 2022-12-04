use std::{sync::Arc, thread, time::Duration};

use avalanche_types::{
    client::{evm as client_evm, wallet},
    key,
};
use aws_manager::{self, cloudwatch};

pub async fn make_transfers(
    spec: blizzardup_aws::Spec,
    cw_manager: Arc<cloudwatch::Manager>,
    chain_id_alias: Arc<String>,
) {
    let _cw_manager: &cloudwatch::Manager = cw_manager.as_ref();
    // TODO: update load testing status in CloudWatch

    let total_rpc_eps = spec.blizzard_spec.rpc_endpoints.len();
    log::info!(
        "STEP 0: start making EVM transfers to {} endpoints with chain id alias {}",
        total_rpc_eps,
        chain_id_alias,
    );

    let mut http_rpcs = Vec::new();
    for ep in spec.blizzard_spec.rpc_endpoints.iter() {
        http_rpcs.push(ep.http_rpc.clone());
    }
    let resp = client_evm::chain_id(&http_rpcs[0], &chain_id_alias)
        .await
        .unwrap();
    let chain_id = resp.result;

    let total_funded_keys = spec.test_keys.len();

    //
    //
    //
    log::info!(
        "STEP 1: finding faucet wallet to fund {} new wallets",
        spec.blizzard_spec.keys_to_generate
    );
    let mut faucet_found = false;
    let mut faucet_idx = random_manager::u8() as usize % total_funded_keys;
    for i in 0..total_funded_keys {
        let idx = (faucet_idx + i) % total_funded_keys;

        let k = key::secp256k1::private_key::Key::from_cb58(
            spec.test_keys[idx].private_key_cb58.clone(),
        )
        .unwrap();

        let faucet_wallet = wallet::Builder::new(&k)
            .http_rpcs(http_rpcs.clone())
            .build()
            .await
            .unwrap();

        let faucet_local_wallet: ethers_signers::LocalWallet = k.signing_key().into();

        let faucet_evm_wallet = faucet_wallet
            .evm(&faucet_local_wallet, chain_id_alias.to_string(), chain_id)
            .unwrap();

        let faucet_bal = faucet_evm_wallet.balance().await.unwrap();
        if !faucet_bal.is_zero() {
            log::info!("faucet wallet found with balance {}", faucet_bal);
            faucet_found = true;
            faucet_idx = idx;
            break;
        }
    }
    if !faucet_found {
        log::warn!("no faucet found with >balance... exiting...");
        return;
    }

    //
    //
    //
    log::info!("STEP 2: loading faucet key and wallet");
    let faucet_key = key::secp256k1::private_key::Key::from_cb58(
        spec.test_keys[faucet_idx].private_key_cb58.clone(),
    )
    .unwrap();

    let faucet_wallet = wallet::Builder::new(&faucet_key)
        .http_rpcs(http_rpcs.clone())
        .build()
        .await
        .unwrap();

    let faucet_local_wallet: ethers_signers::LocalWallet = faucet_key.signing_key().into();

    let faucet_evm_wallet = faucet_wallet
        .evm(&faucet_local_wallet, chain_id_alias.to_string(), chain_id)
        .unwrap();

    log::info!(
        "faucet '{}' can now distribute funds to new keys",
        faucet_key.to_public_key().to_h160()
    );

    //
    //
    //
    log::info!(
        "STEP 3: generating {} ephemeral keys",
        spec.blizzard_spec.keys_to_generate
    );
    let mut ephemeral_test_keys = Vec::new();
    for _ in 0..spec.blizzard_spec.keys_to_generate {
        let k =
            key::secp256k1::private_key::Key::generate().expect("unexpected key generate failure");
        ephemeral_test_keys.push(k);
    }
    log::info!(
        "generated {} ephemeral keys",
        spec.blizzard_spec.keys_to_generate
    );

    //
    //
    //
    // amount to distribute to new keys
    let mut total_to_distribute = primitive_types::U256::from(0);
    let first_addr = ephemeral_test_keys[0].to_public_key().to_h160();
    log::info!(
        "STEP 4: requesting funds from faucet to the first new key {}",
        first_addr
    );
    loop {
        let faucet_bal = match faucet_evm_wallet.balance().await {
            Ok(b) => b,
            Err(e) => {
                log::warn!("failed to get balance {}", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        total_to_distribute = faucet_bal / 100;

        match faucet_evm_wallet
            .eip1559()
            .to(first_addr.clone())
            .value(total_to_distribute)
            .submit()
            .await
        {
            Ok(tx_id) => {
                log::info!(
                    "successfully transferred {} to the first wallet ({})",
                    total_to_distribute,
                    tx_id
                );
                break;
            }
            Err(e) => {
                log::warn!("failed transfer {}", e);
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
    if total_to_distribute.is_zero() {
        log::warn!("zero amount to distribute... exiting...");
        return;
    }

    //
    //
    //
    log::info!(
        "STEP 5: distributing funds from first new key {} to all other keys",
        first_addr
    );
    // TODO

    //
    //
    //
    log::info!("STEP 6: move funds from beginning to end between new keys");
    // TODO
}
