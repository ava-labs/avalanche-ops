use std::{sync::Arc, thread, time::Duration};

use avalanche_types::{client::wallet, key};
use aws_manager::{self, cloudwatch};

pub async fn make_transfers(spec: blizzardup_aws::Spec, cw_manager: Arc<cloudwatch::Manager>) {
    let _cw_manager: &cloudwatch::Manager = cw_manager.as_ref();
    // TODO: update load testing status in CloudWatch

    let total_rpc_eps = spec.blizzard_spec.rpc_endpoints.len();
    log::info!(
        "STEP 0: start making X-chain transfers to {} endpoints",
        total_rpc_eps
    );

    let mut http_rpcs = Vec::new();
    for ep in spec.blizzard_spec.rpc_endpoints.iter() {
        http_rpcs.push(ep.http_rpc.clone());
    }

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

        let faucet_bal = faucet_wallet.x().balance().await.unwrap();
        if faucet_bal > 0 {
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

    log::info!(
        "faucet '{}' can now distribute funds to new keys",
        faucet_key
            .to_public_key()
            .hrp_address(spec.blizzard_spec.network_id, "X")
            .unwrap()
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
    #[allow(unused_assignments)]
    let mut total_to_distribute = 0;
    log::info!(
        "STEP 4: requesting funds from faucet to the first new key {}",
        ephemeral_test_keys[0]
            .to_public_key()
            .hrp_address(spec.blizzard_spec.network_id, "X")
            .unwrap()
    );
    loop {
        let faucet_bal = match faucet_wallet.x().balance().await {
            Ok(b) => b,
            Err(e) => {
                log::warn!("failed to get balance {}", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        total_to_distribute = faucet_bal / 100;

        match faucet_wallet
            .x()
            .transfer()
            .receiver(
                ephemeral_test_keys[0]
                    .to_public_key()
                    .to_short_id()
                    .unwrap(),
            )
            .amount(total_to_distribute)
            .check_acceptance(true)
            .issue()
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
    if total_to_distribute == 0 {
        log::warn!("zero amount to distribute... exiting...");
        return;
    }

    //
    //
    //
    log::info!("STEP 5: loading first key and wallet");
    let first_wallet = wallet::Builder::new(&ephemeral_test_keys[0])
        .http_rpcs(http_rpcs.clone())
        .build()
        .await
        .unwrap();
    log::info!(
        "first key '{}' can now distribute funds to new keys",
        ephemeral_test_keys[0]
            .to_public_key()
            .hrp_address(spec.blizzard_spec.network_id, "X")
            .unwrap()
    );

    //
    //
    //
    log::info!(
        "STEP 6: distributing funds from first new key {} to all other keys",
        ephemeral_test_keys[0]
            .to_public_key()
            .hrp_address(spec.blizzard_spec.network_id, "X")
            .unwrap()
    );
    let to_distribute = total_to_distribute as f64 * 0.9; // save some for gas
    let deposit_amount = to_distribute / spec.blizzard_spec.keys_to_generate as f64; // amount to transfer for each new key
    let deposit_amount = deposit_amount as u64;
    for i in 1..spec.blizzard_spec.keys_to_generate {
        log::info!(
            "transferring {} from {} to {}",
            deposit_amount,
            ephemeral_test_keys[0]
                .to_public_key()
                .hrp_address(spec.blizzard_spec.network_id, "X")
                .unwrap(),
            ephemeral_test_keys[i]
                .to_public_key()
                .hrp_address(spec.blizzard_spec.network_id, "X")
                .unwrap()
        );

        loop {
            match first_wallet
                .x()
                .transfer()
                .receiver(
                    ephemeral_test_keys[i]
                        .to_public_key()
                        .to_short_id()
                        .unwrap(),
                )
                .amount(deposit_amount)
                .check_acceptance(true)
                .issue()
                .await
            {
                Ok(tx_id) => {
                    log::info!(
                        "successfully deposited {} from the first wallet ({})",
                        deposit_amount,
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
    }

    //
    //
    //
    log::info!("STEP 6: looping funds from beginning to end between new keys");
    // only move 1/10-th of remaining balance
    let transfer_amount = deposit_amount / 10;
    loop {
        for i in 0..spec.blizzard_spec.keys_to_generate {
            log::info!(
                "transferring {} from {} to {}",
                transfer_amount,
                ephemeral_test_keys[i]
                    .to_public_key()
                    .hrp_address(spec.blizzard_spec.network_id, "X")
                    .unwrap(),
                ephemeral_test_keys[(i + 1) % spec.blizzard_spec.keys_to_generate]
                    .to_public_key()
                    .hrp_address(spec.blizzard_spec.network_id, "X")
                    .unwrap()
            );

            let source_wallet = wallet::Builder::new(&ephemeral_test_keys[i])
                .http_rpcs(http_rpcs.clone())
                .build()
                .await
                .unwrap();

            loop {
                match source_wallet
                    .x()
                    .transfer()
                    .receiver(
                        ephemeral_test_keys[(i + 1) % spec.blizzard_spec.keys_to_generate]
                            .to_public_key()
                            .to_short_id()
                            .unwrap(),
                    )
                    .amount(transfer_amount)
                    .check_acceptance(true)
                    .issue()
                    .await
                {
                    Ok(tx_id) => {
                        log::info!("successfully transferred {} ({})", transfer_amount, tx_id);
                        break;
                    }
                    Err(e) => {
                        log::warn!("failed transfer {}", e);
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
        }
    }
}
