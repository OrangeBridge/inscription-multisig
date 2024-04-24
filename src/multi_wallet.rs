use anyhow::{bail, Result};
use bdk::bitcoin::blockdata::witness;
use bdk::bitcoin::psbt::{self, PartiallySignedTransaction, Psbt};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Address, Network, OutPoint, PrivateKey, Script, Transaction, TxIn, TxOut, Txid, Witness};
use bdk::bitcoincore_rpc::json::Utxo;
use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcSyncParams};
use bdk::blockchain::{Blockchain, ElectrumBlockchain, GetTx, RpcConfig};
use bdk::database::{Database, MemoryDatabase};
use bdk::miniscript::descriptor::TapTree;
use bdk::miniscript::policy::Concrete;
use bdk::miniscript::psbt::PsbtExt;
use bdk::miniscript::Descriptor;
use bdk::psbt::PsbtUtils;
use bdk::signer::{SignerContext, SignerOrdering, SignerWrapper};
use bdk::sled::{self, Db, Tree};

use bdk::blockchain::ConfigurableBlockchain;
use bdk::wallet::coin_selection::{CoinSelectionAlgorithm, CoinSelectionResult, LargestFirstCoinSelection};
use bdk::wallet::tx_builder::TxOrdering;
use bdk::wallet::{coin_selection, wallet_name_from_descriptor, AddressIndex, AddressInfo};
use bdk::{electrum_client, FeeRate, KeychainKind, LocalUtxo, SignOptions, TransactionDetails, Wallet, WeightedUtxo};
use dotenv::dotenv;
use ordinals::SatPoint;
use std::collections::BTreeMap;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use crate::brc20::{self, BalanceResponse, Brc20};
use crate::ord_client::{AddArgs, InscribeOutput, Inscription, OrdClient};

/* TODOS:
    1. implement custom errors later
    2. request pub key from rest api  async
    3. init in multisig pass name to generate new wallet each time
*/
#[derive(Debug)]
pub struct MultiWallet {
    pub m: u8,
    pub wallet: Wallet<Tree>,
    pub ord: OrdClient,
    pub blockchain: RpcBlockchain,
    pub unspendable: Vec<OutPoint>,
    pub ordinals_api_url:String,
    pub db:Db,
    pub wallet_name:String,
}

impl MultiWallet {
    /* CONSIDER: uniquie multisig each time based on name */
    pub async fn new(
        m: u8,
        pub_keys: Vec<String>,
        datadir: String,
        network: bdk::bitcoin::Network,
        rpc_url: String,
        auth: Auth,
        ordinals_api_url:String
    ) -> Result<MultiWallet> {

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
        let database = sled::open(datadir.clone()).unwrap();
        let db_tree = database.open_tree(wallet_name.clone()).unwrap();

        let wallet = Wallet::new(descriptor.to_string().as_str(), None, network, db_tree)?;


        // Setup the RPC configuration
        let rpc_config = RpcConfig {
            url: rpc_url,
            auth: auth.clone(),
            network,
            wallet_name:wallet_name.clone(),
            sync_params: Some(RpcSyncParams::default()),
        };

        let blockchain = RpcBlockchain::from_config(&rpc_config).unwrap();
        if(network== Network::Bitcoin){
            let client = electrum_client::Client::new("ssl://electrum.blockstream.info:50002")?;
            let blockchain_e = ElectrumBlockchain::from(client);
            wallet.sync(&blockchain_e, bdk::SyncOptions { progress: None })?;
        }
        else{
            wallet.sync(&blockchain, bdk::SyncOptions { progress: None })?;
        }
        let _ord = OrdClient::new(auth, network).await?;

        // mig have to get unspendable from db ^^^^^^^^^^^^^^^^^^^^^^
        Ok(MultiWallet {
            m,
            wallet,
            blockchain,
            unspendable: vec![],
            ord: _ord,
            ordinals_api_url,
            db:database,
            wallet_name
        })
    }

    fn get_Address(&self)->Result<AddressInfo>{
        let address = self.wallet.get_internal_address(AddressIndex::New)?;
        return Ok(address);
    }
    pub fn sync(&self) ->Result<()>{
       self.wallet.sync(&self.blockchain, bdk::SyncOptions { progress: None })?;
       Ok(())
    }
    /**
     * inscribe transferable to multisig address
     */
    pub async fn inscribe_transferable(&self,ticker:String,amount:f64)->Result<InscribeOutput>{
        let available = self.check_available(ticker.clone(), amount).await?;
        if !available{
            bail!("not enough avaiable")
        }
        let address = self.wallet.get_address(AddressIndex::Peek(0))?;
        let brc20 = Brc20::new_transfer(ticker, amount);
        let inscription = self.ord.inscribe_brc20(brc20, address.address, &self.blockchain).await?;
        Ok(inscription)
    }
    /**
     * create a psbt to transfer inscription
     */
    pub fn transfer_insc_zero_fee(&self,inscription:Inscription,to:Address)->Result<(Psbt, TransactionDetails)> {
        let wallet_policy = self.wallet.policies(KeychainKind::External)?.unwrap();
        let mut path = BTreeMap::new();
        path.insert(wallet_policy.id, vec![1]);
        let mut tx_builder = self.wallet.build_tx().coin_selection(LargestFirstCoinSelection);
        let _ = self.sync();
        let utxo = self.get_utxo(inscription.location)?;
        tx_builder
        .ordering(TxOrdering::Untouched)
        .policy_path(path, KeychainKind::External)
        .add_utxo(utxo.outpoint)?
        .add_recipient(to.script_pubkey(), utxo.txout.value)
        .enable_rbf();
        
        let (mut psbt, _details) = tx_builder.finish()?;


  

        // get location of utxo should and what location is in psbt


        Ok((psbt, _details))
    }

    pub fn transfer_insc_psbt(&self,inscription:Inscription,to:Address)->Result<PartiallySignedTransaction>{
        let satpoint = SatPoint::from_str(inscription.location.as_str())?;  
    
        let utxo = self.get_utxo(inscription.location)?;

        let prev_tx_id = Txid::from_str(satpoint.outpoint.txid.to_string().as_str()).unwrap();
        let prev_out_index =  satpoint.outpoint.vout; 
        let prev_out_script = utxo.txout.script_pubkey;
        let prev_out_value = utxo.txout.value; // 0.01127776 BTC


        let recipient_script = to.script_pubkey();
        let transfer_amount = prev_out_value; 

        let input = TxIn {
            previous_output: OutPoint::new(prev_tx_id, prev_out_index),
            script_sig: Script::new(),
            sequence: bdk::bitcoin::Sequence(0xFFFFFFFD),
            witness:Witness::new(),
        };

        let recipient_output = TxOut {
            value: transfer_amount,
            script_pubkey: recipient_script,
        };
        let transaction = Transaction {
            version: 2,
            lock_time: bdk::bitcoin::PackedLockTime(0),
            input: vec![input],
            output: vec![recipient_output],
        };

        
        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(transaction).unwrap();
        // temp sol if works remove and set gas to none
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: prev_out_value,
            script_pubkey: prev_out_script,
        });
        return  Ok(psbt);
    }
    pub fn update_unspendable(&self,outpoint:OutPoint)->Result<()>{
        let db_tree = self.db.open_tree(format!("{}_unspendable",self.wallet_name)).unwrap();
        let mut unspendable:Vec<OutPoint> = vec![];
        if let Some(utxo_vec) = db_tree.get("unspendable")? {
            unspendable= bincode::deserialize(&utxo_vec)?;
            unspendable.push(outpoint);
            
            println!("UTXO: {:?}", unspendable);
        }
        else {
            unspendable = vec![outpoint];
        }
        let data = bincode::serialize(&unspendable)?;
        db_tree.insert("unspendable", data)?;
        Ok(())
    }
    pub fn get_unspendable(&self)->Result<Vec<OutPoint>>{
        let db_tree = self.db.open_tree(format!("{}_unspendable",self.wallet_name)).unwrap();
        if let Some(utxo_vec) = db_tree.get("unspendable")? {
            let  unspendable:Vec<OutPoint>= bincode::deserialize(&utxo_vec)?;
            Ok(unspendable)
        }
        else{
            return  Ok(vec![])
        }
    }


    //npm run dev
    pub async fn check_available(&self,ticker:String,amount:f64)->Result<bool>{
        if self.wallet.network() == Network::Bitcoin {
            let address = self.wallet.get_address(AddressIndex::Peek(0))?;  
            let query = format!("{}/ordinals/v1/brc-20/balances/{}?ticker={}",self.ordinals_api_url,address,ticker);
            let balance_out:BalanceResponse = reqwest::get(query)
                    .await?
                    .json::<BalanceResponse>()
                    .await?;

            if !balance_out.results.is_empty() {
                let available = balance_out.results[0].is_available(amount);
                return Ok(available);
            } else {
               return Ok(false);
            }            
        }
        else{
            return  Ok(true);
        }

    }

    fn get_utxo(&self,location:String)->Result<LocalUtxo>{
        let satpoint = SatPoint::from_str(location.as_str())?;                
        let outpoint = OutPoint::from_str(satpoint.outpoint.to_string().as_str())?;
        let utxo = self.wallet.get_utxo(outpoint)?.unwrap();
        return Ok(utxo);
    }
}

#[tokio::test]
pub async fn test_getWallet() {
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Regtest,
        "http://127.0.0.1:18443".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(wallet) => println!("{:?}", wallet),
        Err(err) => println!("{}", err),
    }
}


#[tokio::test]
async fn get_address() {
    let wallet = Wallet::new(
        // TODO: insert your descriptor here
        "tr(020202020202020202020202020202020202020202020202020202020202020202,multi_a(2,03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1,02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423,02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04))#wahxnw0v",
        None,
        Network::Regtest,
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


#[tokio::test]
async fn inscribe_brc_transfer(){
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Regtest,
        "http://127.0.0.1:18443".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(wallet) => {

            let ins = wallet.inscribe_transferable("test".to_string(), 2323.2).await;
            match  ins {
                Ok(ins) => {
                    println!("inscription :{:?}",ins);
                },
                Err(er) => {
                    panic!("failed to inscribe :{}",er);
                },
            }

        }
        Err(err) => println!("{}", err),
    }
}
#[tokio::test]
async fn xfer_insc_psbt(){
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Regtest,
        "http://127.0.0.1:18443".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(mut wallet) => {
            let ins = Inscription{
                id:"976eae362028377038df78af762595811cd7649c3b8f8db42d8f105e7d70628di0".to_string(),
                location:"976eae362028377038df78af762595811cd7649c3b8f8db42d8f105e7d70628d:0:0".to_string()
            };
            let to = Address::from_str("bcrt1p0qln2gy2me7rdd2f77ua4rc2r5lq2qz2tlfrex8xfzwaeq25hg0qxnpksl").ok().unwrap();
            let psbt = wallet.transfer_insc_zero_fee(ins,to);
            match  psbt {
                Ok(psbt) => {
                    print!("psbt:{}",psbt.0);  
                    print!("inputs:{:#?}",psbt.0.inputs);
                    print!("outputs:{:#?}",psbt.0.outputs);
                },
                Err(err) => {
                    println!("error:{}",err)
                },
            }
        }
        Err(err) => println!("{}", err),
    }
}

#[tokio::test]
async fn sign_psbt(){
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Regtest,
        "http://127.0.0.1:18443".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(mut wallet) => {
               let mut _psbt = PartiallySignedTransaction::from_str("cHNidP8BALIBAAAAAo1icH1eEI8ttI2PO5xk1xyBlSV2r3jfOHA3KCA2rm6XAAAAAAD9////CboNIjXtFIUuY3nJ9rE8zdYtImP5UacEHMUTtZZWUtgAAAAAAP3///8CIgIAAAAAAAAiUSB4PzUgit58NrVJ97najwodPgUASl/SPJjmSJ3cgVS6HsPwBSoBAAAAIlEgUfeAHSzyahK/PquvEnW+iZ6KZrqhOxQOIkbWxQBmD4iHAQAAAAEBKyICAAAAAAAAIlEgUfeAHSzyahK/PquvEnW+iZ6KZrqhOxQOIkbWxQBmD4giFcACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmkg275QK6mnEQwcLcDdLy/HHqEjsweCHCzCZT/0ktOT1LGsIEJe1BWxrAoCIE55p0I8W0dr9b0oH2X5CfoS4A4eS1QjuiDpnya4E6FWomTtOp/khujD7tTDpuYpBDhiy5tQgyA7BLpSnMAhFgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIRbpnya4E6FWomTtOp/khujD7tTDpuYpBDhiy5tQgyA7BCUBSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ/GahbcIRZCXtQVsawKAiBOeadCPFtHa/W9KB9l+Qn6EuAOHktUIyUBSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ99HTkeIRbbvlArqacRDBwtwN0vL8ceoSOzB4IcLMJlP/SS05PUsSUBSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ/iw+IbARcgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBGCBJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpDwABASsA8gUqAQAAACJRIFH3gB0s8moSvz6rrxJ1vomeima6oTsUDiJG1sUAZg+IIhXAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJpINu+UCuppxEMHC3A3S8vxx6hI7MHghwswmU/9JLTk9SxrCBCXtQVsawKAiBOeadCPFtHa/W9KB9l+Qn6EuAOHktUI7og6Z8muBOhVqJk7Tqf5Ibow+7Uw6bmKQQ4YsubUIMgOwS6UpzAIRYCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEW6Z8muBOhVqJk7Tqf5Ibow+7Uw6bmKQQ4YsubUIMgOwQlAUnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykPxmoW3CEWQl7UFbGsCgIgTnmnQjxbR2v1vSgfZfkJ+hLgDh5LVCMlAUnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykPfR05HiEW275QK6mnEQwcLcDdLy/HHqEjsweCHCzCZT/0ktOT1LElAUnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykP4sPiGwEXIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICARggSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ8AAAEFIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAQZrAMBoINu+UCuppxEMHC3A3S8vxx6hI7MHghwswmU/9JLTk9SxrCBCXtQVsawKAiBOeadCPFtHa/W9KB9l+Qn6EuAOHktUI7og6Z8muBOhVqJk7Tqf5Ibow+7Uw6bmKQQ4YsubUIMgOwS6UpwhBwICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIQfpnya4E6FWomTtOp/khujD7tTDpuYpBDhiy5tQgyA7BCUBSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ/GahbcIQdCXtQVsawKAiBOeadCPFtHa/W9KB9l+Qn6EuAOHktUIyUBSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ99HTkeIQfbvlArqacRDBwtwN0vL8ceoSOzB4IcLMJlP/SS05PUsSUBSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ/iw+IbAA==").unwrap();
               let private_key = PrivateKey::from_str("KwJyhCrEK6ARVZ6qdNaCGjyjvp86EduTvEz7HZiZZyL7RiWvXxzi").ok().unwrap();
               let signer = SignerWrapper::new(private_key, SignerContext::Tap { is_internal_key: false });

               wallet.wallet.add_signer(
                   KeychainKind::External,
                   SignerOrdering(0),
                   Arc::new(signer)
               );
               let finalized = wallet.wallet.sign(&mut _psbt, SignOptions::default()).unwrap();
               println!(" status:{} psbt_signed:{}", finalized,_psbt);
        }
        Err(err) => println!("{}", err),
    }
}

#[tokio::test]
async fn combine_broadcast(){
    let wallet = MultiWallet::new(
        2,
        vec![
            "03dbbe502ba9a7110c1c2dc0dd2f2fc71ea123b307821c2cc2653ff492d393d4b1".to_string(),
            "02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423".to_string(),
            "02e99f26b813a156a264ed3a9fe486e8c3eed4c3a6e629043862cb9b5083203b04".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Regtest,
        "http://127.0.0.1:18443".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(wallet) => {
            let mut base_psbt = PartiallySignedTransaction::from_str("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").unwrap();
            let signed_psbts = vec![
                 // TODO: Paste each participant's PSBT here
                 "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",
                 "cHNidP8BALIBAAAAAo1icH1eEI8ttI2PO5xk1xyBlSV2r3jfOHA3KCA2rm6XAAAAAAD9////CboNIjXtFIUuY3nJ9rE8zdYtImP5UacEHMUTtZZWUtgAAAAAAP3///8CIgIAAAAAAAAiUSB4PzUgit58NrVJ97najwodPgUASl/SPJjmSJ3cgVS6HsPwBSoBAAAAIlEgUfeAHSzyahK/PquvEnW+iZ6KZrqhOxQOIkbWxQBmD4iHAQAAAAEBKyICAAAAAAAAIlEgUfeAHSzyahK/PquvEnW+iZ6KZrqhOxQOIkbWxQBmD4hBFEJe1BWxrAoCIE55p0I8W0dr9b0oH2X5CfoS4A4eS1QjSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ9AmpXMztOkHCgzCy7Qt3FlQ6bnp03L5P8bL7RsyBoJZhYu1hCatDlOjlSEZh89oBaMMk0FKClRgp/qzqEfVjZqRCIVwAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSDbvlArqacRDBwtwN0vL8ceoSOzB4IcLMJlP/SS05PUsawgQl7UFbGsCgIgTnmnQjxbR2v1vSgfZfkJ+hLgDh5LVCO6IOmfJrgToVaiZO06n+SG6MPu1MOm5ikEOGLLm1CDIDsEulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFumfJrgToVaiZO06n+SG6MPu1MOm5ikEOGLLm1CDIDsEJQFJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpD8ZqFtwhFkJe1BWxrAoCIE55p0I8W0dr9b0oH2X5CfoS4A4eS1QjJQFJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpD30dOR4hFtu+UCuppxEMHC3A3S8vxx6hI7MHghwswmU/9JLTk9SxJQFJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpD+LD4hsBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYIEnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykPAAEBKwDyBSoBAAAAIlEgUfeAHSzyahK/PquvEnW+iZ6KZrqhOxQOIkbWxQBmD4hBFEJe1BWxrAoCIE55p0I8W0dr9b0oH2X5CfoS4A4eS1QjSdK8lwZd0O+zLWSCuIS45pjy/zFiqWfTjLltPbRDKQ9AUPR+RQEVVUpTPVv4HB61xrp205RvSTlfmbGAoCf/7YPbH+W54q3AYU2vDTeWcTL+5Sga9PRNVwDoxzVRQV9cNCIVwAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSDbvlArqacRDBwtwN0vL8ceoSOzB4IcLMJlP/SS05PUsawgQl7UFbGsCgIgTnmnQjxbR2v1vSgfZfkJ+hLgDh5LVCO6IOmfJrgToVaiZO06n+SG6MPu1MOm5ikEOGLLm1CDIDsEulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFumfJrgToVaiZO06n+SG6MPu1MOm5ikEOGLLm1CDIDsEJQFJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpD8ZqFtwhFkJe1BWxrAoCIE55p0I8W0dr9b0oH2X5CfoS4A4eS1QjJQFJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpD30dOR4hFtu+UCuppxEMHC3A3S8vxx6hI7MHghwswmU/9JLTk9SxJQFJ0ryXBl3Q77MtZIK4hLjmmPL/MWKpZ9OMuW09tEMpD+LD4hsBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYIEnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykPAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCDbvlArqacRDBwtwN0vL8ceoSOzB4IcLMJlP/SS05PUsawgQl7UFbGsCgIgTnmnQjxbR2v1vSgfZfkJ+hLgDh5LVCO6IOmfJrgToVaiZO06n+SG6MPu1MOm5ikEOGLLm1CDIDsEulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEH6Z8muBOhVqJk7Tqf5Ibow+7Uw6bmKQQ4YsubUIMgOwQlAUnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykPxmoW3CEHQl7UFbGsCgIgTnmnQjxbR2v1vSgfZfkJ+hLgDh5LVCMlAUnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykPfR05HiEH275QK6mnEQwcLcDdLy/HHqEjsweCHCzCZT/0ktOT1LElAUnSvJcGXdDvsy1kgriEuOaY8v8xYqln04y5bT20QykP4sPiGwA="
                 ];
        
            for psbt in signed_psbts {
                let psbt = PartiallySignedTransaction::from_str(psbt).unwrap();
                base_psbt.combine(psbt).ok();
            }
        
            let secp = Secp256k1::new();
            let psbt = base_psbt.finalize(&secp).unwrap();
            let finalized_tx = psbt.extract_tx();
            dbg!(finalized_tx.txid());
            dbg!(wallet.blockchain.broadcast(&finalized_tx)).ok();
        }
        Err(err) => println!("{}", err),
    }

}

