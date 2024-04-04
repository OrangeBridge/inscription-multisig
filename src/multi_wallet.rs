use anyhow::{bail, Result};
use bdk::bitcoin::psbt::{PartiallySignedTransaction, Psbt};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{ Address, Network};

use bdk::bitcoincore_rpc::Client;
use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcSyncParams};
use bdk::blockchain::{ElectrumBlockchain, RpcConfig};
use bdk::database::MemoryDatabase;
use bdk::miniscript::descriptor::TapTree;
use bdk::miniscript::policy::Concrete;
use bdk::miniscript::Descriptor;
use bdk::sled::{self, Tree};
use bdk::wallet::coin_selection::BranchAndBoundCoinSelection;
use bdk::wallet::tx_builder::CreateTx;
use bdk::wallet::{self, wallet_name_from_descriptor, AddressIndex};
use bdk::blockchain::{ConfigurableBlockchain, NoopProgress};
use bdk::{  electrum_client, FeeRate, KeychainKind, SyncOptions, TransactionDetails, TxBuilder, Wallet};
use dotenv::dotenv;
use std::collections::BTreeMap;
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
            network,
            wallet_name,
            sync_params: Some(RpcSyncParams::default())
        };

        let blockchain = RpcBlockchain::from_config(&rpc_config).unwrap();
        let client = electrum_client::Client::new("ssl://electrum.blockstream.info:50002")?;
        let blockchain_e = ElectrumBlockchain::from(client);
       
        // use electrum for initial sync for speed
        wallet.sync(&blockchain_e, bdk::SyncOptions { progress: None })?;
       
       
        Ok(MultiWallet {
            pub_keys: new_keys,
            m,
            wallet,
            blockchain,
        })
    }

    // fun below is for testing psbt functionality remove 
    fn inscribe_brc20_transfer(){

    }
    
    fn create_psbt_drain(&self) -> Result<(Psbt, TransactionDetails)>{
            let wallet_policy = self.wallet.policies(KeychainKind::External)?.unwrap();
            let mut path = BTreeMap::new();
            path.insert(wallet_policy.id, vec![1]);
            // remove fauce bleow is only
            let faucet_address = Address::from_str("tb1ql7w62elx9ucw4pj5lgw4l028hmuw80sndtntxt")?;
            let mut tx_builder = self.wallet.build_tx();
            tx_builder
                .drain_wallet()
                .drain_to(faucet_address.script_pubkey())
                .fee_rate(FeeRate::from_sat_per_vb(3.0))
                .policy_path(path, KeychainKind::External);
        
            let (psbt, _details) = tx_builder.finish()?;
            println!("psbt {} details {:?}",psbt,_details);
            Ok((psbt,_details))

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
        "http://127.0.0.1:8332".to_string(),
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


#[test]
fn pst_creation(){
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Bitcoin,
        "http://127.0.0.1:8332".to_string(),
        Auth::UserPass { username:"user".to_string(), password: "pass".to_string() }
        
    );
    match wallet {
        Ok(wallet) =>{

            let psbt = wallet.create_psbt_drain();
        },
        Err(err) => println!("{}", err),
    }
}