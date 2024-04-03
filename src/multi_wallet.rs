use anyhow::{bail, Result};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{ Network};

use bdk::blockchain::rpc::{Auth, RpcBlockchain};
use bdk::blockchain::RpcConfig;
use bdk::database::MemoryDatabase;
use bdk::miniscript::descriptor::TapTree;
use bdk::miniscript::policy::Concrete;
use bdk::miniscript::Descriptor;
use bdk::sled::{self, Tree};
use bdk::wallet::{wallet_name_from_descriptor, AddressIndex};
use bdk::blockchain::{ConfigurableBlockchain, NoopProgress};
use bdk::{  SyncOptions, Wallet};
use dotenv::dotenv;
use std::sync::Arc;
use std::str::FromStr;

/* TODOS:
    1. implement custom errors later
    2. request pub key from rest api  async
    3. init in multisig pass name to generate new wallet each time
*/
#[derive(Debug)]
struct MultiWallet {
    pub pub_keys: Vec<String>,
    pub m: u8,
    pub wallet: Wallet<Tree>,
    pub blockchain:RpcBlockchain
}
impl MultiWallet {
    /* CONSIDER: uniquie multisig each time based on name */
    fn new(
        m: u8,
        pub_keys: Vec<String>,
        datadir: String,
        network: bdk::bitcoin::Network,
        rpc_url: String,
        auth: Auth,
    ) -> Result<MultiWallet> {
        init();
        let n = pub_keys.len();
        if usize::from(m) > n {
            bail!("Number of required keys cannot be greater than total");
        }
        let new_keys = pub_keys.clone();
        let keys_joined: String = pub_keys
            .into_iter()
            .map(|k| format!("pk({})", k))
            .collect::<Vec<_>>()
            .join(",");
        let first_policy_str = format!("thresh({},{})", m, keys_joined);
        let first_policy = Concrete::<String>::from_str(&first_policy_str)?.compile()?;
        let first_tap_leaf = TapTree::Leaf(Arc::new(first_policy));

        let dummy_internal =
            "020202020202020202020202020202020202020202020202020202020202020202".to_string();
        let descriptor = Descriptor::new_tr(dummy_internal, Some(first_tap_leaf))?;
        println!("{} descriptor", descriptor);

        let wallet_name = wallet_name_from_descriptor(
            descriptor.to_string().as_str(),
            None,
            network,
            &Secp256k1::new(),
        )?;
        let database = sled::open(datadir).unwrap();
        let db_tree = database.open_tree(wallet_name.clone()).unwrap();

        let wallet = Wallet::new(
            descriptor.to_string().as_str(),
            None,
            network,
            db_tree,
        )?;
        
        println!("walletname {}", wallet_name);

        // Setup the RPC configuration
        let rpc_config = RpcConfig {
            url: rpc_url,
            auth,
            network: Network::Regtest,
            wallet_name,
            sync_params: None,
        };

        let blockchain = RpcBlockchain::from_config(&rpc_config).unwrap();
        // sync once
        wallet.sync(&blockchain, SyncOptions::default())?;
        Ok(MultiWallet {
            pub_keys: new_keys,
            m,
            wallet,
            blockchain,
            
        })
    }
}

#[test]
pub fn test_getWallet() {
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Bitcoin,
        "https://127.0.0.1:8333".to_string(),
        Auth::UserPass { username:"user".to_string(), password: "pass".to_string() }
        
    );
    match wallet {
        Ok(wallet) => println!("{:?}", wallet),
        Err(err) => println!("{}", err),
    }
}

pub fn init() {
    dotenv().ok();
}
#[test]
fn get_address() {
    let wallet = Wallet::new(
        // TODO: insert your descriptor here
        "tr(020202020202020202020202020202020202020202020202020202020202020202,multi_a(2,03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1,02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423,02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04))#wahxnw0v",
        None,
        Network::Testnet,
        MemoryDatabase::new()
    );
    match wallet {
        Ok(wallet) => {
            if let Ok(address) = wallet.get_internal_address(AddressIndex::New) {
                println!("{} address", address);
            } else {
                print!("failed to load address")
            }
            if let Ok(address) = wallet.get_address(AddressIndex::New) {
                println!("{} address", address);
            } else {
                print!("failed to load address")
            }
        }
        Err(_) => {}
    }
}
