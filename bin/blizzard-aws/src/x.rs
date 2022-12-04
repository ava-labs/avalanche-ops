use std::sync::Arc;

use avalanche_types::{client::wallet, key};
use aws_manager::{self, cloudwatch};

pub async fn make_transfers(spec: blizzardup_aws::Spec, cw_manager: Arc<cloudwatch::Manager>) {
    let _cw_manager: &cloudwatch::Manager = cw_manager.as_ref();
    // TODO: update load testing status in CloudWatch

    let total_rpc_eps = spec.blizzard_spec.rpc_endpoints.len();
    log::info!(
        "start making X-chain transfers to {} endpoints",
        total_rpc_eps
    );

    let mut http_rpcs = Vec::new();
    for ep in spec.blizzard_spec.rpc_endpoints.iter() {
        http_rpcs.push(ep.http_rpc.clone());
    }

    let total_funded_keys = spec.test_keys.len();

    log::info!(
        "finding faucet wallet to fund {} new wallets",
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
        log::warn!("no faucet found with >balance");
        return;
    }

    let faucet_key = key::secp256k1::private_key::Key::from_cb58(
        spec.test_keys[faucet_idx].private_key_cb58.clone(),
    )
    .unwrap();
    log::info!(
        "faucet wallet '{}' will distribute funds to new keys",
        faucet_key
            .to_public_key()
            .hrp_address(spec.blizzard_spec.network_id, "X")
            .unwrap()
    );

    log::info!(
        "generating {} ephemeral keys",
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
}
