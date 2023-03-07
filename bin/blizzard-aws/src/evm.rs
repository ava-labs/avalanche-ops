use std::collections::HashMap;

use avalanche_types::{jsonrpc::client::evm as jsonrpc_client_evm, key, wallet};
use tokio::time::{sleep, Duration};

pub async fn make_transfers(worker_idx: usize, spec: blizzardup_aws::Spec) {
    let total_rpc_eps = spec.blizzard_spec.chain_rpc_urls.len();
    let total_funded_keys = spec.prefunded_key_infos.len();
    log::info!(
        "[WORKER #{worker_idx}] STEP 1: start making EVM transfers to {total_rpc_eps} endpoints (total funded keys {total_funded_keys})"
    );

    let chain_rpc_urls = spec.blizzard_spec.chain_rpc_urls.clone();
    let chain_id = jsonrpc_client_evm::chain_id(&chain_rpc_urls[0])
        .await
        .unwrap();

    //
    //
    //
    //
    //
    log::info!(
        "[WORKER #{worker_idx}] STEP 2: finding faucet wallet to fund {} new keys",
        spec.blizzard_spec.keys_to_generate
    );
    let mut faucet_found = false;
    let mut faucet_idx = random_manager::usize() % total_funded_keys;
    for i in 0..total_funded_keys {
        let idx = (faucet_idx + i) % total_funded_keys;

        let k = key::secp256k1::private_key::Key::from_cb58(
            spec.prefunded_key_infos[idx]
                .private_key_cb58
                .clone()
                .unwrap(),
        )
        .unwrap();

        let faucet_wallet = wallet::Builder::new(&k)
            .base_http_urls(chain_rpc_urls.clone())
            .build()
            .await
            .unwrap();

        let faucet_local_wallet: ethers_signers::LocalWallet =
            k.to_ethers_core_signing_key().into();

        let faucet_evm_wallet = faucet_wallet
            .evm(
                &faucet_local_wallet,
                &chain_rpc_urls[i % chain_rpc_urls.len()],
                chain_id,
            )
            .unwrap();

        let faucet_bal = match faucet_evm_wallet.balance().await {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "[WORKER #{worker_idx}] failed to get faucet wallet balance '{}' -- checking next faucet wallet",
                    e
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        if !faucet_bal.is_zero() {
            log::info!(
                "[WORKER #{worker_idx}] faucet wallet found with non-zero balance {}",
                faucet_bal
            );
            faucet_found = true;
            faucet_idx = idx;
            break;
        }
    }
    if !faucet_found {
        log::warn!("[WORKER #{worker_idx}] no faucet found with >balance... exiting...");
        return;
    }

    //
    //
    //
    //
    //
    log::info!("[WORKER #{worker_idx}] STEP 3: loading faucet key and wallet");
    let faucet_key = key::secp256k1::private_key::Key::from_cb58(
        spec.prefunded_key_infos[faucet_idx]
            .private_key_cb58
            .clone()
            .unwrap(),
    )
    .unwrap();

    let faucet_wallet = wallet::Builder::new(&faucet_key)
        .base_http_urls(chain_rpc_urls.clone())
        .build()
        .await
        .unwrap();

    let faucet_local_wallet: ethers_signers::LocalWallet =
        faucet_key.to_ethers_core_signing_key().into();

    let faucet_evm_wallet = faucet_wallet
        .evm(&faucet_local_wallet, &chain_rpc_urls[0], chain_id)
        .unwrap();

    log::info!(
        "[WORKER #{worker_idx}] faucet '{}' can now distribute funds to new keys",
        faucet_key.to_public_key().to_h160()
    );

    //
    //
    //
    //
    //
    log::info!(
        "[WORKER #{worker_idx}] STEP 4: generating {} ephemeral keys",
        spec.blizzard_spec.keys_to_generate
    );
    let mut ephemeral_test_keys = Vec::new();
    for _ in 0..spec.blizzard_spec.keys_to_generate {
        let k =
            key::secp256k1::private_key::Key::generate().expect("unexpected key generate failure");
        ephemeral_test_keys.push(k);
    }
    log::info!(
        "[WORKER #{worker_idx}] generated {} ephemeral keys",
        spec.blizzard_spec.keys_to_generate
    );

    //
    //
    //
    //
    //
    // amount to distribute to new keys
    #[allow(unused_assignments)]
    let mut total_to_distribute = primitive_types::U256::zero();
    log::info!(
        "[WORKER #{worker_idx}] STEP 5: requesting a bulk of funds from faucet to the first generated new key {}",
        ephemeral_test_keys[0].to_public_key().to_h160()
    );
    loop {
        log::info!("[WORKER #{worker_idx}] getting faucet wallet balance");
        let faucet_bal = match faucet_evm_wallet.balance().await {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "[WORKER #{worker_idx}] failed to get faucet wallet balance '{}' -- TODO: for now, just use 10000000000000000000000",
                    e
                );

                // TODO: retries...
                // sleep(Duration::from_secs(5)).await;
                // continue;

                primitive_types::U256::from_dec_str("10000000000000000000000").unwrap()
            }
        };
        log::info!(
            "[WORKER #{worker_idx}] successfully got faucet wallet balance '{}'",
            faucet_bal
        );
        total_to_distribute = faucet_bal / 100;

        // do not set nonce, so we can fetch the latest
        match faucet_evm_wallet
            .eip1559()
            .recipient(ephemeral_test_keys[0].to_public_key().to_h160())
            .value(total_to_distribute)
            .urgent()
            .submit()
            .await
        {
            Ok(tx_id) => {
                log::info!(
                    "[WORKER #{worker_idx}] successfully transferred {} from faucet to first wallet ({})",
                    total_to_distribute,
                    tx_id
                );
                break;
            }
            Err(e) => {
                log::warn!("[WORKER #{worker_idx}] failed transfer {}", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
    if total_to_distribute.is_zero() {
        log::warn!("[WORKER #{worker_idx}] zero amount to distribute... exiting...");
        return;
    }

    //
    //
    //
    //
    //
    log::info!("[WORKER #{worker_idx}] STEP 6: loading first generated new key and wallet");
    let first_ephemeral_wallet = wallet::Builder::new(&ephemeral_test_keys[0])
        .base_http_urls(chain_rpc_urls.clone())
        .build()
        .await
        .unwrap();

    let first_ephemeral_local_wallet: ethers_signers::LocalWallet =
        ephemeral_test_keys[0].to_ethers_core_signing_key().into();

    let first_ephemeral_evm_wallet = first_ephemeral_wallet
        .evm(&first_ephemeral_local_wallet, &chain_rpc_urls[0], chain_id)
        .unwrap();

    log::info!(
        "[WORKER #{worker_idx}] first generated new key '{}' can now distribute funds to new keys",
        ephemeral_test_keys[0].to_public_key().to_h160()
    );

    log::info!(
        "[WORKER #{worker_idx}] STEP 7: initializing signer nonce cache for all ephemeral keys"
    );
    // cache the nonce assuming the key is unique with no other user
    let mut h160_to_nonce: HashMap<primitive_types::H160, primitive_types::U256> = HashMap::new();
    for i in 0..spec.blizzard_spec.keys_to_generate {
        h160_to_nonce.insert(
            ephemeral_test_keys[i].to_public_key().to_h160(),
            primitive_types::U256::zero(),
        );
    }

    //
    //
    //
    //
    //
    log::info!(
        "[WORKER #{worker_idx}] STEP 8: distributing funds from first generated new key {} to all other keys",
        ephemeral_test_keys[0].to_public_key().to_h160()
    );
    // save some for gas, only use 90%
    let to_distribute = total_to_distribute
        .checked_div(primitive_types::U256::from(10))
        .unwrap();
    let to_distribute = to_distribute
        .checked_mul(primitive_types::U256::from(9))
        .unwrap();
    // amount to transfer for each new key
    let deposit_amount = to_distribute
        .checked_div(primitive_types::U256::from(
            spec.blizzard_spec.keys_to_generate,
        ))
        .unwrap();

    let sender_h160 = ephemeral_test_keys[0].to_public_key().to_h160();
    for i in 1..spec.blizzard_spec.keys_to_generate {
        let receiver_h160 = ephemeral_test_keys[i].to_public_key().to_h160();
        log::info!(
            "[WORKER #{worker_idx}-{}] transferring {} from {} to {}",
            i,
            deposit_amount,
            sender_h160,
            receiver_h160
        );

        let sender_nonce = h160_to_nonce.get(&sender_h160).unwrap().clone();
        loop {
            match first_ephemeral_evm_wallet
                .eip1559()
                .recipient(receiver_h160)
                .value(deposit_amount)
                .signer_nonce(sender_nonce)
                .urgent()
                .submit()
                .await
            {
                Ok(tx_id) => {
                    log::info!(
                        "[WORKER #{worker_idx}-{}] successfully deposited {} from the first wallet to the other ephemeral key ({})",
                        i,
                        deposit_amount,
                        tx_id
                    );

                    h160_to_nonce.insert(sender_h160, primitive_types::U256::from(i));
                    break;
                }
                Err(e) => {
                    log::warn!("[WORKER #{worker_idx}-{}] failed transfer '{}' from the first wallet to the other ephemeral key", i, e);

                    // e.g., (code: -32000, message: nonce too low: address 0x557FDFCAEff5daDF7287344f4E30172e56EC7aec current nonce (1) > tx nonce (0), data: None)
                    if e.to_string().contains("nonce too low") {
                        log::info!("retrying latest nonce fetch");
                        let new_nonce = first_ephemeral_evm_wallet.middleware.next();
                        h160_to_nonce.insert(sender_h160, new_nonce);
                    }

                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    //
    //
    //
    //
    //
    log::info!("[WORKER #{worker_idx}] STEP 9: load keys to wallets");
    let mut ephmeral_wallets = Vec::new();
    for i in 0..spec.blizzard_spec.keys_to_generate {
        let wallet = wallet::Builder::new(&ephemeral_test_keys[i])
            .base_http_urls(chain_rpc_urls.clone())
            .build()
            .await
            .unwrap();
        ephmeral_wallets.push(wallet);
    }

    //
    //
    //
    //
    //
    log::info!(
        "[WORKER #{worker_idx}] STEP 10: looping funds from beginning to end between new keys"
    );
    // only move 1/10-th of remaining balance
    let transfer_amount = deposit_amount
        .checked_div(primitive_types::U256::from(10))
        .unwrap();
    loop {
        for i in 0..spec.blizzard_spec.keys_to_generate {
            let sender_h160 = ephemeral_test_keys[i].to_public_key().to_h160();
            let receiver_h160 = ephemeral_test_keys[(i + 1) % spec.blizzard_spec.keys_to_generate]
                .to_public_key()
                .to_h160();

            log::info!(
                "[WORKER #{worker_idx}-{}] transferring {} from {} to {}",
                i,
                transfer_amount,
                sender_h160,
                receiver_h160
            );

            let local_wallet: ethers_signers::LocalWallet =
                ephemeral_test_keys[i].to_ethers_core_signing_key().into();

            let evm_wallet = ephmeral_wallets[i]
                .evm(
                    &local_wallet,
                    &chain_rpc_urls[i % chain_rpc_urls.len()],
                    chain_id,
                )
                .unwrap();

            let sender_nonce = h160_to_nonce.get(&sender_h160).unwrap().clone();
            loop {
                match evm_wallet
                    .eip1559()
                    .recipient(receiver_h160)
                    .value(transfer_amount)
                    .signer_nonce(sender_nonce)
                    .urgent()
                    .submit()
                    .await
                {
                    Ok(tx_id) => {
                        log::info!(
                            "[WORKER #{worker_idx}-{}] successfully transferred {} between ephemeral keys ({})",
                            i,
                            transfer_amount,
                            tx_id
                        );

                        h160_to_nonce.insert(
                            sender_h160,
                            sender_nonce
                                .checked_add(primitive_types::U256::from(1))
                                .unwrap(),
                        );
                        break;
                    }
                    Err(e) => {
                        log::warn!(
                            "[WORKER #{worker_idx}-{}] failed transfer '{}' between ephemeral keys",
                            i,
                            e
                        );

                        // e.g., (code: -32000, message: nonce too low: address 0x557FDFCAEff5daDF7287344f4E30172e56EC7aec current nonce (1) > tx nonce (0), data: None)
                        if e.to_string().contains("nonce too low") {
                            log::info!("retrying latest nonce fetch");
                            let new_nonce = evm_wallet.middleware.next();
                            h160_to_nonce.insert(sender_h160, new_nonce);
                        }

                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }
}
