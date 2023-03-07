use avalanche_types::{key, wallet};
use tokio::time::{sleep, Duration};

pub async fn make_transfers(worker_idx: usize, spec: blizzardup_aws::Spec) {
    let total_rpc_eps = spec.blizzard_spec.chain_rpc_urls.len();
    let network_id = spec.status.clone().unwrap().network_id;
    let total_funded_keys = spec.prefunded_key_infos.len();

    log::info!(
        "[WORKER #{worker_idx}] STEP 1: start making X-chain transfers to {total_rpc_eps} endpoints (network id {network_id}, total funded keys {total_funded_keys})"
    );

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
            .base_http_urls(spec.blizzard_spec.chain_rpc_urls.clone())
            .build()
            .await
            .unwrap();

        let faucet_bal = match faucet_wallet.x().balance().await {
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

        if faucet_bal > 0 {
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
        .base_http_urls(spec.blizzard_spec.chain_rpc_urls.clone())
        .build()
        .await
        .unwrap();

    log::info!(
        "[WORKER #{worker_idx}] faucet '{}' can now distribute funds to new keys",
        faucet_key
            .to_public_key()
            .to_hrp_address(network_id, "X")
            .unwrap()
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
    let mut total_to_distribute = 0;
    log::info!(
        "[WORKER #{worker_idx}] STEP 5: requesting a bulk of funds from faucet to the first generated new key {}",
        ephemeral_test_keys[0]
            .to_public_key()
            .to_hrp_address(network_id, "X")
            .unwrap()
    );

    let receiver_short_addr = ephemeral_test_keys[0]
        .to_public_key()
        .to_short_id()
        .unwrap();
    loop {
        log::info!("[WORKER #{worker_idx}] getting faucet wallet balance");
        let faucet_bal = match faucet_wallet.x().balance().await {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "[WORKER #{worker_idx}] failed to get faucet wallet balance '{}'",
                    e
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        log::info!(
            "[WORKER #{worker_idx}] successfully got faucet wallet balance '{}'",
            faucet_bal
        );
        total_to_distribute = faucet_bal / 100;

        match faucet_wallet
            .x()
            .transfer()
            .receiver(receiver_short_addr.clone())
            .amount(total_to_distribute)
            .check_acceptance(true)
            .issue()
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
    if total_to_distribute == 0 {
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
        .base_http_urls(spec.blizzard_spec.chain_rpc_urls.clone())
        .build()
        .await
        .unwrap();
    log::info!(
        "[WORKER #{worker_idx}] first generated new key '{}' can now distribute funds to new keys",
        ephemeral_test_keys[0]
            .to_public_key()
            .to_hrp_address(network_id, "X")
            .unwrap()
    );

    //
    //
    //
    //
    //
    log::info!(
        "[WORKER #{worker_idx}] STEP 7: distributing funds from first generated new key {} to all other keys",
        ephemeral_test_keys[0]
            .to_public_key()
            .to_hrp_address(network_id, "X")
            .unwrap()
    );
    // save some for gas
    let to_distribute = total_to_distribute as f64 * 0.9;
    // amount to transfer for each new key
    let deposit_amount = to_distribute / spec.blizzard_spec.keys_to_generate as f64;
    let deposit_amount = deposit_amount as u64;
    for i in 1..spec.blizzard_spec.keys_to_generate {
        log::info!(
            "[WORKER #{worker_idx}-{}] transferring {} from {} to {}",
            i,
            deposit_amount,
            ephemeral_test_keys[0]
                .to_public_key()
                .to_hrp_address(network_id, "X")
                .unwrap(),
            ephemeral_test_keys[i]
                .to_public_key()
                .to_hrp_address(network_id, "X")
                .unwrap()
        );

        let receiver_short_addr = ephemeral_test_keys[i]
            .to_public_key()
            .to_short_id()
            .unwrap();
        loop {
            match first_ephemeral_wallet
                .x()
                .transfer()
                .receiver(receiver_short_addr.clone())
                .amount(deposit_amount)
                .check_acceptance(true)
                .issue()
                .await
            {
                Ok(tx_id) => {
                    log::info!(
                        "[WORKER #{worker_idx}-{}] successfully deposited {} from the first wallet to the other ephemeral key ({})",
                        i,
                        deposit_amount,
                        tx_id
                    );
                    break;
                }
                Err(e) => {
                    log::warn!("[WORKER #{worker_idx}-{}] failed transfer {}", i, e);
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
    log::info!("[WORKER #{worker_idx}] STEP 8: load keys to wallets");
    let mut ephmeral_wallets = Vec::new();
    for i in 0..spec.blizzard_spec.keys_to_generate {
        let wallet = wallet::Builder::new(&ephemeral_test_keys[i])
            .base_http_urls(spec.blizzard_spec.chain_rpc_urls.clone())
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
        "[WORKER #{worker_idx}] STEP 9: looping funds from beginning to end between new keys"
    );
    // only move 1/10-th of remaining balance
    let transfer_amount = deposit_amount / 10;
    loop {
        for i in 0..spec.blizzard_spec.keys_to_generate {
            log::info!(
                "[WORKER #{worker_idx}-{}] transferring {} from {} to {}",
                i,
                transfer_amount,
                ephemeral_test_keys[i]
                    .to_public_key()
                    .to_hrp_address(network_id, "X")
                    .unwrap(),
                ephemeral_test_keys[(i + 1) % spec.blizzard_spec.keys_to_generate]
                    .to_public_key()
                    .to_hrp_address(network_id, "X")
                    .unwrap()
            );

            let receiver_short_addr = ephemeral_test_keys
                [(i + 1) % spec.blizzard_spec.keys_to_generate]
                .to_public_key()
                .to_short_id()
                .unwrap();
            loop {
                match ephmeral_wallets[i]
                    .x()
                    .transfer()
                    .receiver(receiver_short_addr.clone())
                    .amount(transfer_amount)
                    .check_acceptance(true)
                    .issue()
                    .await
                {
                    Ok(tx_id) => {
                        log::info!(
                            "[WORKER #{worker_idx}-{}] successfully transferred {} between ephemeral keys ({})",
                            i,
                            transfer_amount,
                            tx_id
                        );
                        break;
                    }
                    Err(e) => {
                        log::warn!("[WORKER #{worker_idx}-{}] failed transfer {}", i, e);
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }
}
