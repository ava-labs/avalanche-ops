use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use crate::flags;
use avalanche_types::{
    codec::serde::hex_0x_primitive_types_h160::Hex0xH160,
    errors,
    jsonrpc::client::{evm as jsonrpc_client_evm, info as jsonrpc_client_info},
    key::secp256k1::{self, private_key},
    units, utils,
    wallet::{
        self,
        evm::{self as wallet_evm, Evm},
        Wallet,
    },
};
use ethers_providers::{Http, Provider, RetryClient};
use futures_util::{Stream, StreamExt};
use governor::{
    clock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use primitive_types::{H160, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::{sse::Event, Filter};

/// ref. <https://github.com/seanmonstar/warp/blob/master/examples/sse_chat.rs>
/// ref. <https://github.com/madmaxio/tokio/blob/master/warp/examples/sse_chat.rs>
pub async fn execute(opts: flags::Options) -> io::Result<()> {
    println!("starting {} with {:?}", crate::APP_NAME, opts);

    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    log::info!("checking RPC endpoints for network Id");
    let mut network_id = 0;
    for ep in opts.chain_rpc_urls.iter() {
        let resp = jsonrpc_client_info::get_network_id(ep).await.unwrap();

        let prev = network_id;
        network_id = resp.result.unwrap().network_id;

        log::info!("{ep} returned network id {network_id}");

        if prev != 0 && prev != network_id {
            panic!("different network id found from rpc {prev} != {network_id}");
        };
    }

    let mut chain_rpc_health_urls = Vec::new();
    let mut chain_rpc_providers = HashMap::new();
    for ep in opts.chain_rpc_urls.iter() {
        let (scheme, host, port, _, _) =
            utils::urls::extract_scheme_host_port_path_chain_alias(ep).unwrap();
        let u = if let Some(scheme) = scheme {
            if let Some(port) = port {
                format!("{scheme}://{host}:{port}/ext/health")
            } else {
                format!("{scheme}://{host}/ext/health")
            }
        } else {
            format!("http://{host}/ext/health")
        };
        chain_rpc_health_urls.push(u);

        let chain_rpc_provider = wallet_evm::new_provider(
            ep,
            Duration::from_secs(15),
            Duration::from_secs(30),
            10,
            Duration::from_secs(3),
        )
        .unwrap();
        chain_rpc_providers.insert(ep.clone(), chain_rpc_provider);
    }

    let picked_chain_rpc_url =
        opts.chain_rpc_urls[random_manager::usize() % opts.chain_rpc_urls.len()].clone();
    let chain_id = jsonrpc_client_evm::chain_id(&picked_chain_rpc_url)
        .await
        .unwrap();
    log::info!("chain Id {chain_id}");

    let keys = Keys::load(&opts.keys_file).unwrap();
    keys.validate().unwrap();
    let loaded_hot_wallets = keys
        .load_wallets(network_id, chain_id, opts.chain_rpc_urls.clone())
        .await
        .unwrap();

    let loaded_hot_wallets_arc = Arc::new(loaded_hot_wallets);
    let loaded_hot_wallets = warp::any().map(move || loaded_hot_wallets_arc.clone());

    // Keep track of all connected users, key is usize, value
    // is an event stream sender.
    let users = Arc::new(Mutex::new(HashMap::new()));
    // Turn our "state" into a new Filter...
    let users = warp::any().map(move || users.clone());

    let connected_chain_rpc_health_urls_arc = Arc::new(chain_rpc_health_urls);
    let connected_health_urls =
        warp::any().map(move || connected_chain_rpc_health_urls_arc.clone());

    let chain_id_arc = Arc::new(chain_id);
    let chain_id = warp::any().map(move || chain_id_arc.clone());

    let chain_rpc_urls_arc = Arc::new(opts.chain_rpc_urls.clone());
    let chain_rpc_urls = warp::any().map(move || chain_rpc_urls_arc.clone());
    let chain_rpc_providers_arc = Arc::new(chain_rpc_providers);
    let chain_rpc_providers = warp::any().map(move || chain_rpc_providers_arc.clone());

    // POST /chat -> send message
    let chat_send = warp::path("chat")
        .and(warp::post())
        .and(warp::path::param::<usize>())
        .and(warp::body::content_length_limit(500))
        .and(
            warp::body::bytes().and_then(|body: bytes::Bytes| async move {
                std::str::from_utf8(&body)
                    .map(String::from)
                    .map_err(|_e| warp::reject::custom(NotUtf8))
            }),
        )
        .and(users.clone())
        .then(|sender_id, _msg, users| async move {
            // discard message for security reasons
            handle_chat_post(sender_id, &users);
            warp::reply()
        });

    // GET /chat -> messages stream
    let chat_recv = warp::path("chat")
        .and(warp::get())
        .and(users.clone())
        .and(connected_health_urls.clone())
        .and(chain_id.clone())
        .and(chain_rpc_urls.clone())
        .then(
            |users: UserIds,
             connected_health_urls: Arc<Vec<String>>,
             chain_id: Arc<U256>,
             chain_rpc_urls: Arc<Vec<String>>| async move {
                // reply using server-sent events
                let stream =
                    handle_chat_get(users, connected_health_urls, chain_id, chain_rpc_urls);
                warp::sse::reply(warp::sse::keep_alive().stream(stream))
            },
        );

    // only 1 request per 10-second
    let rpc_rate_limiter_arc = Arc::new(RateLimiter::direct(
        Quota::with_period(Duration::from_secs(10)).unwrap(),
    ));
    let rpc_rate_limiter = warp::any().map(move || rpc_rate_limiter_arc.clone());

    // POST /check-balance -> send message
    let check_balance_send = warp::path("check-balance")
        .and(warp::post())
        .and(warp::path::param::<usize>())
        .and(warp::body::content_length_limit(100)) // prevent too long of user name
        .and(
            warp::body::bytes().and_then(|body: bytes::Bytes| async move {
                std::str::from_utf8(&body)
                    .map(String::from)
                    .map_err(|_e| warp::reject::custom(NotUtf8))
            }),
        )
        .and(users.clone())
        .and(connected_health_urls.clone())
        .and(chain_id.clone())
        .and(chain_rpc_urls.clone())
        .and(rpc_rate_limiter.clone())
        .then(
            |user_id: usize,
             address_to_check: String,
             users: UserIds,
             connected_health_urls: Arc<Vec<String>>,
             chain_id: Arc<U256>,
             chain_rpc_urls: Arc<Vec<String>>,
             rpc_rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, clock::DefaultClock, NoOpMiddleware>>| async move {
                let connected_health_urls = connected_health_urls.as_ref();
                let chain_rpc_urls = chain_rpc_urls.as_ref();
                match rpc_rate_limiter.check() {
                    Ok(_) => {
                        log::info!("not throttled");
                    }
                    Err(e) => {
                        log::warn!(
                            "throttled with rate limiter (error '{}')",
                            e,
                        );
                        users.lock().unwrap().retain(|uid, v| {
                            if user_id == *uid {
                                v.notifier
                                    .send(NotifyEvent {
                                        sender_user_id: user_id,
                                        msg: Message::Reply(format!("throttled with rate limiter (error '{}')", e)),
                                    })
                                    .unwrap();
                            }
                            true
                        });
                        return warp::reply::json(&UserInfo {
                            user_id: user_id,
                            user_address: H160::zero(),
                            connected_health_urls: connected_health_urls.clone(),
                            connected_chain_id: *chain_id.clone(),
                            connected_chain_id_u64: chain_id.as_u64(),
                            connected_chain_rpc_urls: chain_rpc_urls.clone(),
                            error: String::new(),
                        });
                    }
                };

                let picked_rpc = chain_rpc_urls[random_manager::usize() % chain_rpc_urls.len()].clone();
                let (msg, addr) = match H160::from_str(address_to_check.trim_start_matches("0x")) {
                        Ok(addr) => {
                            let balance = jsonrpc_client_evm::get_balance(&picked_rpc, addr)
                                .await
                                .unwrap();
                            (
                                format!(
                                    "user id {user_id} with 0x{:x} has balance {} ({} ETH/AVAX)",
                                    addr,
                                    balance,
                                    units::cast_evm_navax_to_avax_i64(balance)
                                ),
                                addr,
                            )
                        }
                        Err(e) => (
                            format!("user id {user_id} failed to parse address {address_to_check} (error {:?})", e),
                            H160::zero(),
                        ),
                    };

                users.lock().unwrap().retain(|uid, v| {
                    if user_id == *uid {
                        v.address = addr;
                        v.notifier
                            .send(NotifyEvent {
                                sender_user_id: user_id,
                                msg: Message::Reply(msg.clone()),
                            })
                            .unwrap();
                    }
                    true
                });

                warp::reply::json(&UserInfo {
                    user_id: user_id,
                    user_address: addr,
                    connected_health_urls: connected_health_urls.clone(),
                    connected_chain_id: *chain_id.clone(),
                    connected_chain_id_u64: chain_id.as_u64(),
                    connected_chain_rpc_urls: chain_rpc_urls.clone(),
                    error: String::new(),
                })
            },
        );

    // POST /request-fund -> send message
    let request_fund_send = warp::path("request-fund")
        .and(warp::post())
        .and(warp::path::param::<usize>())
        .and(warp::body::content_length_limit(500))
        .and(
            warp::body::bytes().and_then(|body: bytes::Bytes| async move {
                std::str::from_utf8(&body)
                    .map(String::from)
                    .map_err(|_e| warp::reject::custom(NotUtf8))
            }),
        )
        .and(users.clone())
        .and(connected_health_urls.clone())
        .and(chain_id.clone())
        .and(chain_rpc_urls.clone())
        .and(chain_rpc_providers.clone())
        .and(loaded_hot_wallets.clone())
        .and(rpc_rate_limiter.clone())
        .then(
            |user_id: usize,
             address_to_fund: String,
             users: UserIds,
             connected_health_urls: Arc<Vec<String>>,
             chain_id: Arc<U256>,
             chain_rpc_urls: Arc<Vec<String>>,
             chain_rpc_providers: Arc<HashMap<String, Provider<RetryClient<Http>>>>,
             loaded_hot_wallets: Arc<Vec<HotWallet>>,
             rpc_rate_limiter: Arc<
                RateLimiter<NotKeyed, InMemoryState, clock::DefaultClock, NoOpMiddleware>,
            >| async move {
                log::info!("{user_id} (address {address_to_fund}) requesting a fund");

                let connected_health_urls = connected_health_urls.as_ref();
                let connected_chain_rpc_urls = chain_rpc_urls.as_ref();
                match rpc_rate_limiter.check() {
                    Ok(_) => {
                        log::info!("not throttled");
                    }
                    Err(e) => {
                        log::warn!("throttled with rate limiter (error '{}')", e,);
                        users.lock().unwrap().retain(|uid, v| {
                            if user_id == *uid {
                                v.notifier
                                    .send(NotifyEvent {
                                        sender_user_id: user_id,
                                        msg: Message::Reply(format!(
                                            "throttled with rate limiter (error '{}')",
                                            e
                                        )),
                                    })
                                    .unwrap();
                            }
                            true
                        });
                        return warp::reply::json(&UserInfo {
                            user_id: user_id,
                            user_address: H160::zero(),
                            connected_health_urls: connected_health_urls.clone(),
                            connected_chain_id: *chain_id.clone(),
                            connected_chain_id_u64: chain_id.as_u64(),
                            connected_chain_rpc_urls: connected_chain_rpc_urls.clone(),
                            error: String::new(),
                        });
                    }
                };

                let picked_rpc = connected_chain_rpc_urls
                    [random_manager::usize() % connected_chain_rpc_urls.len()]
                .clone();
                let _chain_rpc_provider = chain_rpc_providers.get(&picked_rpc).unwrap();

                let key_idx = NEXT_KEY_IDX.fetch_add(1, Ordering::Relaxed);
                let picked_wallet = loaded_hot_wallets[key_idx % loaded_hot_wallets.len()].clone();
                let transferer_evm_wallet = picked_wallet
                    .wallet
                    .evm(&picked_wallet.eth_signer, &picked_rpc, *chain_id)
                    .unwrap();

                let transfer_amount_in_avax = U256::from(1000);
                let transfer_amount =
                    units::cast_avax_to_evm_navax(U256::from(transfer_amount_in_avax));

                let (msg, addr) = match H160::from_str(address_to_fund.trim_start_matches("0x")) {
                    Ok(transferee_addr) => match transferer_evm_wallet
                        .eip1559()
                        .recipient(transferee_addr)
                        .value(units::cast_avax_to_evm_navax(U256::from(1000)))
                        .urgent()
                        .check_acceptance(true)
                        .submit()
                        .await
                    {
                        Ok(tx_id) => {
                            log::info!(
                                "evm ethers wallet SUCCESS with transaction id 0x{:x}",
                                tx_id
                            );
                            (
                                format!(
                                "user id {user_id} sent {} ({} ETH/AVAX to 0x{:x} (tx id 0x{:x})",
                                transfer_amount, transfer_amount_in_avax, transferee_addr, tx_id
                            ),
                                transferee_addr,
                            )
                        }
                        Err(e) => (
                            format!(
                                "user id {user_id} failed to sent fund to 0x{:x} ({:?})",
                                transferee_addr, e
                            ),
                            transferee_addr,
                        ),
                    },
                    Err(e) => (
                        format!(
                        "user id {user_id} failed to parse address {address_to_fund} (error {:?})",
                        e
                    ),
                        H160::zero(),
                    ),
                };

                users.lock().unwrap().retain(|uid, v| {
                    if user_id == *uid {
                        v.address = addr;
                        v.notifier
                            .send(NotifyEvent {
                                sender_user_id: user_id,
                                msg: Message::Reply(msg.clone()),
                            })
                            .unwrap();
                    }
                    true
                });

                warp::reply::json(&UserInfo {
                    user_id: user_id,
                    user_address: addr,
                    connected_health_urls: connected_health_urls.clone(),
                    connected_chain_id: *chain_id.clone(),
                    connected_chain_id_u64: chain_id.as_u64(),
                    connected_chain_rpc_urls: connected_chain_rpc_urls.clone(),
                    error: String::new(),
                })
            },
        );

    // GET / -> index html
    let index = warp::get()
        .and(warp::path::end())
        .map(|| warp::reply::html(include_str!("static/index.html")));

    let routes = index
        .or(chat_recv)
        .or(chat_send)
        .or(check_balance_send)
        .or(request_fund_send);

    warp::serve(routes).run(opts.http_host).await;

    Ok(())
}

/// Our global unique user id counter.
/// TODO(용훈): store and load in the subnet (e.g., key-value store subnet)
static NEXT_USER_ID: AtomicUsize = AtomicUsize::new(1);

/// Global counter for keys.
static NEXT_KEY_IDX: AtomicUsize = AtomicUsize::new(0);

/// Tracks the state of currently connected users.
/// Maps each user Id to its corresponding message sender and its key.
/// TODO(용훈): store and load in the subnet (e.g., key-value store subnet)
/// TODO(용훈): encrypt messages private key, decrypt with public key
type UserIds = Arc<Mutex<HashMap<usize, User>>>;

#[derive(Debug)]
struct User {
    user_id: usize,
    address: H160,
    notifier: mpsc::UnboundedSender<NotifyEvent>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UserInfo {
    pub user_id: usize,
    #[serde_as(as = "Hex0xH160")]
    pub user_address: H160,

    pub connected_health_urls: Vec<String>,
    pub connected_chain_id: U256,
    pub connected_chain_id_u64: u64,
    pub connected_chain_rpc_urls: Vec<String>,

    #[serde(default)]
    pub error: String,
}

/// Message variants.
#[derive(Debug)]
enum Message {
    UserInfo(UserInfo),
    Reply(String),
}

#[derive(Debug)]
struct NotifyEvent {
    sender_user_id: usize,
    msg: Message,
}

fn handle_chat_get(
    users: UserIds,
    connected_health_urls: Arc<Vec<String>>,
    chain_id: Arc<U256>,
    chain_rpc_urls: Arc<Vec<String>>,
) -> impl Stream<Item = Result<Event, warp::Error>> + Send + 'static {
    let created_user_id = NEXT_USER_ID.fetch_add(1, Ordering::Relaxed);
    log::info!("new user connected -- user id {created_user_id}");

    // Use an unbounded channel to handle buffering and flushing of messages
    // to the event source...
    let (tx, rx) = mpsc::unbounded_channel();
    let rx = UnboundedReceiverStream::new(rx);

    let chain_rpc_urls = chain_rpc_urls.as_ref();
    let connected_health_urls = connected_health_urls.as_ref();
    tx.send(NotifyEvent {
        sender_user_id: created_user_id,
        msg: Message::UserInfo(UserInfo {
            user_id: created_user_id,
            user_address: H160::zero(),
            connected_health_urls: connected_health_urls.clone(),
            connected_chain_id: *chain_id.clone(),
            connected_chain_id_u64: chain_id.as_u64(),
            connected_chain_rpc_urls: chain_rpc_urls.clone(),
            error: String::new(),
        }),
    })
    // rx is right above, so this cannot fail
    .unwrap();

    // Save the sender in our list of connected users.
    users.lock().unwrap().insert(
        created_user_id,
        User {
            user_id: created_user_id,
            address: H160::zero(),
            notifier: tx,
        },
    );

    // Create channel to track disconnecting the receiver side of events.
    // This is little bit tricky.
    let (mut dtx, mut drx) = oneshot::channel::<()>();

    // When `drx` will dropped then `dtx` will be canceled.
    // We can track it to make sure when the user leaves chat.
    tokio::spawn(async move {
        dtx.closed().await;
        drx.close();

        log::info!("user {created_user_id} is disconnected (closed stream)");
        users.lock().unwrap().remove(&created_user_id);
    });

    // Convert messages into Server-Sent Events and return resulting stream.
    rx.map(|notify_event| match notify_event.msg {
        Message::UserInfo(user_info) => {
            log::info!("user info");
            Ok(Event::default()
                .event("userConnectedEvent")
                .json_data(user_info)
                .unwrap())
        }
        Message::Reply(reply) => {
            log::info!("reply from (user name {})", notify_event.sender_user_id);
            Ok(Event::default().data(reply))
        }
    })
}

/// TODO(용훈): implements rate limiting to prevent DDoS
fn handle_chat_post(sender_id: usize, users: &UserIds) {
    let sender_user_id = {
        users
            .lock()
            .unwrap()
            .get(&sender_id)
            .unwrap()
            .user_id
            .clone()
    };
    let sender_address = { users.lock().unwrap().get(&sender_id).unwrap().address };

    // New message from this user, send it to everyone else (except same uid)...
    //
    // We use `retain` instead of a for loop so that we can reap any user that
    // appears to have disconnected.
    users.lock().unwrap().retain(|receiver_id, receiver| {
        if sender_id == *receiver_id {
            // don't send to same user, but do retain
            true
        } else {
            let new_msg = format!(
                "[sender id {sender_id} ==> receiver id {}, receiver name {}, 0x{:x}] Hi 👋",
                sender_address, receiver.user_id, receiver.address,
            );

            // If not `is_ok`, the SSE stream is gone, and so don't retain
            // from this user's point of view, the session has been disconnected
            receiver
                .notifier
                .send(NotifyEvent {
                    sender_user_id,
                    msg: Message::Reply(new_msg.clone()),
                })
                .is_ok()
        }
    });
}

#[derive(Debug)]
struct NotUtf8;
impl warp::reject::Reject for NotUtf8 {}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Entry {
    /// Either hex-encoded private key or AWS KMS ARN.
    pub key: String,
}

impl Default for Entry {
    fn default() -> Self {
        Self::default()
    }
}

impl Entry {
    pub fn default() -> Self {
        Self { key: String::new() }
    }
}

#[derive(Debug, Clone)]
pub struct HotWallet {
    pub key: private_key::Key,
    pub eth_signer: ethers_signers::LocalWallet,
    pub wallet: Wallet<private_key::Key>,
    pub key_info: secp256k1::Info,
    pub rpc_to_evm_wallet: HashMap<String, Evm<private_key::Key, ethers_signers::LocalWallet>>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Keys(pub Vec<Entry>);

impl Keys {
    pub fn load(file_path: &str) -> std::io::Result<Self> {
        log::info!("loading from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("file {file_path} does not exists"),
            ));
        }

        let f = File::open(file_path).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to open {file_path} ({e})"),
            )
        })?;
        serde_yaml::from_reader(f).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid YAML: {e}"),
            )
        })
    }

    /// Validates the keys file and returns the set of key Ids.
    pub fn validate(&self) -> std::io::Result<HashSet<String>> {
        log::info!("validating keys file");

        // fail if duplicates are found
        // admin may have inserted duplicate keys... make sure all keys are unique
        // iterate through the "keys" and error if duplicates are found
        let mut found = HashSet::new();
        for entry in self.0.iter() {
            if found.get(&entry.key).is_some() {
                // found in the hash set, we need to error
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "duplicate key found",
                ));
            }
            found.insert(entry.key.clone());
        }

        Ok(found)
    }

    pub async fn load_wallets(
        &self,
        network_id: u32,
        chain_id: U256,
        chain_rpc_urls: Vec<String>,
    ) -> errors::Result<Vec<HotWallet>> {
        let mut hotkeys = Vec::new();
        for (i, k) in self.0.iter().enumerate() {
            let signing_key = private_key::Key::from_hex(&k.key)?;
            let ki = signing_key.to_info(network_id)?;
            log::info!(
                "[{i}] loaded test hotkey {} (network Id {network_id})",
                ki.h160_address,
            );

            let signer: ethers_signers::LocalWallet =
                signing_key.to_ethers_core_signing_key().into();

            let w = wallet::Builder::new(&signing_key)
                .base_http_urls(chain_rpc_urls.clone())
                .build()
                .await?;

            let mut rpc_to_evm_wallet = HashMap::new();
            for chain_rpc_url in &chain_rpc_urls {
                let evm_wallet = w.evm(&signer, chain_rpc_url, chain_id)?;
                rpc_to_evm_wallet.insert(chain_rpc_url.clone(), evm_wallet);
            }

            hotkeys.push(HotWallet {
                key: signing_key,
                eth_signer: signer,
                wallet: w,
                key_info: ki,
                rpc_to_evm_wallet,
            });
        }

        Ok(hotkeys)
    }
}

/// RUST_LOG=debug cargo test --package devnet-faucet --bin devnet-faucet -- command::test_file --exact --show-output
#[test]
fn test_file() {
    use std::io::Write;

    let _ = env_logger::builder().is_test(true).try_init();

    let contents = format!(
        r#"

- key: 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027

"#,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let key_path = f.path().to_str().unwrap();

    let keys = Keys::load(key_path).unwrap();
    assert_eq!(
        keys.0[0].key,
        String::from("56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027")
    );
}
