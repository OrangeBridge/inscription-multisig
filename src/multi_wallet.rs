use anyhow::{bail, Result};
use bdk::bitcoin::blockdata::witness;
use bdk::bitcoin::hashes::sha256d::Hash;
use bdk::bitcoin::policy::get_virtual_tx_size;
use bdk::bitcoin::psbt::{self, Input, PartiallySignedTransaction, Psbt, PsbtSighashType};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Address, EcdsaSighashType, Network, OutPoint, PrivateKey, Script, SigHashType, Transaction, TxIn, TxOut, Txid, Witness};
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
use tokio::sync::broadcast;
use std::collections::BTreeMap;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use crate::brc20::{self, BalanceResponse, Brc20};
use crate::ord_client::{AddArgs, InscribeOutput, Inscription, OrdClient};
use crate::utils::{select_fee_utxo, FeeUtxo, MempoolFeeRate};

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
        // println!("{} descriptor", descriptor);

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

        let db_tree = database.open_tree(format!("{}_unspendable",wallet_name)).unwrap();
        let mut unspendable:Vec<OutPoint> = vec![];
        if let Some(utxo_vec) = db_tree.get("unspendable")? {
            unspendable= bincode::deserialize(&utxo_vec)?;
        }
        // mig have to get unspendable from db ^^^^^^^^^^^^^^^^^^^^^^
        Ok(MultiWallet {
            m,
            wallet,
            blockchain,
            unspendable: unspendable,
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
    pub async fn transfer_insc_zero_fee(&self,inscription:Inscription,to:Address)->Result<(Psbt, TransactionDetails)> {
        let wallet_policy = self.wallet.policies(KeychainKind::External)?.unwrap();
        let mut path = BTreeMap::new();
        path.insert(wallet_policy.id, vec![1]);
        let mut tx_builder = self.wallet.build_tx().coin_selection(LargestFirstCoinSelection);
        let _ = self.sync();
        let utxo: LocalUtxo = self.get_utxo(inscription.location)?;
        let feerate = self.fee_rate_sat_vb().await?;
        tx_builder
        .ordering(TxOrdering::Untouched)
        .policy_path(path, KeychainKind::External)
        .add_utxo(utxo.outpoint)?
        .unspendable(self.unspendable.clone())
        .add_recipient(to.script_pubkey(), utxo.txout.value)
       
        .fee_rate(FeeRate::from_sat_per_vb(feerate))
        .enable_rbf();
        
        let (mut psbt, _details) = tx_builder.finish()?;


  

        // get location of utxo should and what location is in psbt


        Ok((psbt, _details))
    }

  /**
     * create a psbt to transfer inscription
     */
    // ##todo 
    pub async fn transfer_insc_with_fee(&self,inscription:Inscription,to:Address,fee_utxos:Vec<FeeUtxo>)->Result<(Psbt, TransactionDetails)> {
        let wallet_policy = self.wallet.policies(KeychainKind::External)?.unwrap();
        let feeRate = self.fee_rate_sat_vb().await?;
        let mut path = BTreeMap::new();
        path.insert(wallet_policy.id, vec![1]);

        let fee_rate = self.fee_rate_sat_vb().await?;

        let mut tx_builder = self.wallet.build_tx().coin_selection(LargestFirstCoinSelection);
        let _ = self.sync();
        let utxo: LocalUtxo = self.get_utxo(inscription.location)?;
        let sighash_flag = EcdsaSighashType::SinglePlusAnyoneCanPay;
        tx_builder
        .ordering(TxOrdering::Untouched)
        .policy_path(path, KeychainKind::External)
        .add_utxo(utxo.outpoint)?
        .add_recipient(to.script_pubkey(), utxo.txout.value)
        .fee_absolute(0)
        .enable_rbf()
        .sighash(PsbtSighashType::from(sighash_flag))
        .manually_selected_only();
        let (mut psbt, _details) = tx_builder.clone().finish()?;
        let size = psbt.extract_tx().size();     
        let (fee_utxos,fee,covered) = select_fee_utxo(fee_utxos, size, fee_rate)?;
        for utxo in fee_utxos{
            let mut input = Input::default();
            input.witness_utxo = Some(utxo.tx_out);
            tx_builder.add_foreign_utxo(utxo.outpoint, input,100)?;
        }
        if(covered> fee){
            tx_builder.add_recipient(to.script_pubkey(), covered-fee).fee_absolute(fee);
        }
        println!("covered:{} fee:{}",covered,fee);
        let (mut psbt, _details) = tx_builder.finish()?;
        Ok((psbt, _details))
    }

    pub async fn fee_rate_sat_vb(&self)-> Result<f32>{
        let network = self.wallet.network();
        if network == Network::Regtest{
            return Ok(1.0);
        }
        else if network == Network::Bitcoin{
            let res = reqwest::get("https://mempool.space/api/v1/fees/recommended").await;
            match res {
                Ok(res) => {
                    if res.status().is_success() {
                        let fee = res.json::<MempoolFeeRate>().await?;
                        return Ok(fee.fastestFee);
                    } 
                }
                Err(_) => {}
            }
        }

        if let Ok(fee) = self.blockchain.estimate_fee(1) {
            return Ok(fee.as_sat_per_vb());
        } else  {
            bail!("could not estimat gas fee")
        }
    }
    pub fn update_unspendable(&self,outpoint:OutPoint)->Result<()>{
        let db_tree = self.db.open_tree(format!("{}_unspendable",self.wallet_name)).unwrap();
        let mut unspendable:Vec<OutPoint> = vec![];
        if let Some(utxo_vec) = db_tree.get("unspendable")? {
            unspendable= bincode::deserialize(&utxo_vec)?;
            unspendable.push(outpoint);
            
            // println!("UTXO: {:?}", unspendable);
        }
        else {
            unspendable = vec![outpoint];
        }
        let data = bincode::serialize(&unspendable)?;
        db_tree.insert("unspendable", data)?;
        Ok(())
    }
    pub fn remove_unspendable(&self,outpoint:OutPoint)->Result<()>{
        let db_tree = self.db.open_tree(format!("{}_unspendable",self.wallet_name)).unwrap();
        let mut unspendable:Vec<OutPoint> = vec![];
        if let Some(utxo_vec) = db_tree.get("unspendable")? {
            unspendable= bincode::deserialize(&utxo_vec)?;
            unspendable.retain(|utxo| utxo.txid ==outpoint.txid && utxo.vout == outpoint.vout);
        }
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
        Ok(wallet) =>{
       
            if let Ok(address) = wallet.wallet.get_internal_address(AddressIndex::New) {
                println!("{} address", address);
            } else {
                print!("failed to load address")
            }
            if let Ok(address) = wallet.wallet.get_address(AddressIndex::New) {
                println!("{} address", address);
            } else {
                print!("failed to load address")
            }
            
        }
        Err(err) => println!("{}", err),
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

            let ins = wallet.inscribe_transferable("bepi".to_string(), 25.2).await;
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
            
        ],
        "./wallet_test".to_string(),
        Network::Bitcoin,
        "http://127.0.0.1:8332".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(mut wallet) => {
            let ins = Inscription{
                id:"49388d8407c203ea24c1031c7732e40aa0213acc7a751d9fbfbde54bd6eb22bbi0".to_string(),
                location:"49388d8407c203ea24c1031c7732e40aa0213acc7a751d9fbfbde54bd6eb22bb:0:0".to_string()
            };
            let to = Address::from_str("bc1pmwhc9f0nxelj5qxj6v784nmmlqcpe6dad0vzs0l4rz7wp6y3d36seytgv6").ok().unwrap();
            
            let tx_out = TxOut{
                value:51784, script_pubkey: 
                Script::from_str("5120dbaf82a5f3367f2a00d2d33c7acf7bf8301ce9bd6bd8283ff518bce0e8916c75").unwrap()
            };
            let txid: Txid = Txid::from_str("3df36765919094eb32f22b831d74a5954ba1695346ef04fb947ba2871d6da5d7").unwrap();
            let outpoint= OutPoint::new(txid, 1);

            let tx_out2 = TxOut{
                value:3552, script_pubkey: 
                Script::from_str("5120dbaf82a5f3367f2a00d2d33c7acf7bf8301ce9bd6bd8283ff518bce0e8916c75").unwrap()
            };
            let txid2: Txid = Txid::from_str("5dbb37539d85dacbcf5644e41dc11a2d0b90b1c67b4985e45060024929a54f97").unwrap();
            let outpoint2= OutPoint::new(txid, 1);


            let fee1 = FeeUtxo{
                outpoint:outpoint,
                tx_out:tx_out,
                weight:100
            };
            let fee2 = FeeUtxo{
                outpoint:outpoint2,
                tx_out:tx_out2,
                weight:100
            };
            let psbt = wallet.transfer_insc_with_fee(ins,to,vec![fee1,fee2]).await;
            match  psbt {
                Ok(psbt) => {
                    println!("psbt:{}",psbt.0);  
                    let tx = psbt.0.clone().extract_tx();
                    println!("tx:{:#?}",tx);
                    let fee = psbt.0.fee_rate().unwrap();
                    
                    println!("feeRate:{}",fee.as_sat_per_vb());
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
            "037032d63a356a821804b204bc6fb6f768e160fefb36888edad296ab9f0ad88a33".to_string(),
            "029469e94e617fb421b9298feeb0d3f7e901948b536803bde97da7752fe90c95e0".to_string(),
            "0393f448b315936fe3d38610fd61f15f893c3d8af8dc4dbaeacb35093f827e5820".to_string()
        ],
        "./wallet_test".to_string(),
        Network::Bitcoin,
        "http://127.0.0.1:8332".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(mut wallet) => {
               let mut _psbt = PartiallySignedTransaction::from_str("cHNidP8BALIBAAAAArsi69ZL5b2/nx11esw6IaAK5DJ3HAPBJOoDwgeEjThJAAAAAAD9////16VtHYeie5T7BO9GU2mhS5WldB2DK/Iy65SQkWVn8z0BAAAAAP3///8CIgIAAAAAAAAiUSDbr4Kl8zZ/KgDS0zx6z3v4MBzpvWvYKD/1GLzg6JFsdUjKAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hc5gwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3gBAwSDAAAAIhXBAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJpIHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozrCCUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4Logk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCC6UpzAIRYCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEWk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEWcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEWlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwEXIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICARgg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpwAAQErSMoAAAAAAAAiUSDbr4Kl8zZ/KgDS0zx6z3v4MBzpvWvYKD/1GLzg6JFsdQAAAQUgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBBmsAwGggcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijOsIJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXguiCT9EizFZNv49OGEP1h8V+JPD2K+NxNuurLNQk/gn5YILpSnCEHAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhB5P0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhB3Ay1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhB5Rp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcA").unwrap();
               let private_key = PrivateKey::from_str("").ok().unwrap();
               let signer = SignerWrapper::new(private_key, SignerContext::Tap { is_internal_key: false });

               wallet.wallet.add_signer(
                   KeychainKind::External,
                   SignerOrdering(0),
                   Arc::new(signer)
               );
               let sighash_flag = EcdsaSighashType::SinglePlusAnyoneCanPay;
               let mut options = SignOptions::default();
               options.allow_all_sighashes =true;
               options.trust_witness_utxo = true;
               let finalized = wallet.wallet.sign(&mut _psbt, options).unwrap();
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
            "037032d63a356a821804b204bc6fb6f768e160fefb36888edad296ab9f0ad88a33".to_string(),
            "029469e94e617fb421b9298feeb0d3f7e901948b536803bde97da7752fe90c95e0".to_string(),
            "0393f448b315936fe3d38610fd61f15f893c3d8af8dc4dbaeacb35093f827e5820".to_string(),
        ],
        "./wallet_test".to_string(),
        Network::Bitcoin,
        "http://127.0.0.1:8332".to_string(),
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string()
    ).await;
    match wallet {
        Ok(wallet) => {
            let mut base_psbt = PartiallySignedTransaction::from_str("cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3giFcECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmkgcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijOsIJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXguiCT9EizFZNv49OGEP1h8V+JPD2K+NxNuurLNQk/gn5YILpSnMAhFgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIRaT9EizFZNv49OGEP1h8V+JPD2K+NxNuurLNQk/gn5YICUB24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0Rlpw4HqXhIRZwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKMyUB24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0Rlpwc6RVDIRaUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4CUB24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpzYt2h3ARcgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBGCDbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnAABAStAnAAAAAAAACJRIF0uvROIbIDKTvJU//yKtM41J8YwytNddRtsJTO7VjN4IhXBAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJpIHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozrCCUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4Logk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCC6UpzAIRYCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEWk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEWcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEWlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwEXIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICARgg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpwAAAEFIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAQZrAMBoIHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozrCCUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4Logk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCC6UpwhBwICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIQeT9EizFZNv49OGEP1h8V+JPD2K+NxNuurLNQk/gn5YICUB24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0Rlpw4HqXhIQdwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKMyUB24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0Rlpwc6RVDIQeUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4CUB24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpzYt2h3AA==").unwrap();
            let signed_psbts = vec![
                 // TODO: Paste each participant's PSBT here
                 "cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2Ioz24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxARRoVmkL+sveMsj7R6iyPXzL0Y7WDVCdM9hYlbwQKPPCToySBaPzbnsIZYO6oWyNb3+Nj9Qvc3bi91tihNdUokyIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAEBK0CcAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2Ioz24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxArTFaduuc4dzmejdmAwvScZEMosugic73uw5MTxmmsPl2LtCduF8255BJgVt6VPo/I3F1CTyDCy7453CBK+Hy/iIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEHk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEHcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEHlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwA=",
                 "cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxAizNkIn1FcBqiktX5TvOLxRk5iKQklW/jCZwQuUPniE0FQrl/M9Ry0P7MhbA+kD/imUtQ+TW80X5jXfOKeR5kISIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAEBK0CcAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxADFfsqur7pY++eW9rMNAI0AJuFtSfydNYnVq7wOQtNGL5IZGUHXDLNw4i8NH7acA87mySOTekGOuPvD6c5OW0uSIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEHk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEHcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEHlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwA="
                 ];
        
            for psbt in signed_psbts {
                let psbt = PartiallySignedTransaction::from_str(psbt).unwrap();
                base_psbt.combine(psbt).ok();
            }

            let secp = Secp256k1::new();
            let psbt = base_psbt.finalize(&secp).unwrap();
            let finalized_tx = psbt.extract_tx();
            dbg!(finalized_tx.txid());
            let broadcast = wallet.blockchain.broadcast(&finalized_tx);
            match  broadcast {
                Ok(_) => {println!(" succesfullt broadcasted")},
                Err(err) =>{println!("error:{}",err)}
            }
        }
        Err(err) => println!("{}", err),
    }

}

// // #[tokio::test]
// // async fn test(){
//     let wallet = MultiWallet::new(
//         2,
//         vec![
//             "037032d63a356a821804b204bc6fb6f768e160fefb36888edad296ab9f0ad88a33".to_string(),
//             "029469e94e617fb421b9298feeb0d3f7e901948b536803bde97da7752fe90c95e0".to_string(),
//             "0393f448b315936fe3d38610fd61f15f893c3d8af8dc4dbaeacb35093f827e5820".to_string(),
//         ],
//         "./wallet_test".to_string(),
//         Network::Bitcoin,
//         "http://127.0.0.1:8332".to_string(),
//         Auth::UserPass {
//             username: "user".to_string(),
//             password: "pass".to_string(),
//         },
//         "https://api.hiro.so".to_string()
//     ).await;
//     match wallet {
//         Ok(wallet) => {
//             let mut base_psbt = PartiallySignedTransaction::from_str("cHNidP8BAF4BAAAAAd69M75rD3ywxe+2W8UzI43KrrBXZxK/RnoXp8di1/KIAAAAAAD9////ASICAAAAAAAAIlEg26+CpfM2fyoA0tM8es97+DAc6b1r2Cg/9Ri84OiRbHUf5gwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3gBAwSDAAAAIhXBAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJpIHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozrCCUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4Logk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCC6UpzAIRYCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEWk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEWcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEWlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwEXIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICARgg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpwAAA==").unwrap();
//             let signed_psbts = vec![
//                  // TODO: Paste each participant's PSBT here
//                  "cHNidP8BAF4BAAAAAd69M75rD3ywxe+2W8UzI43KrrBXZxK/RnoXp8di1/KIAAAAAAD9////ASICAAAAAAAAIlEg26+CpfM2fyoA0tM8es97+DAc6b1r2Cg/9Ri84OiRbHUf5gwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3gBAwSDAAAAQRRwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM9uEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacQZLZjHL3SS37pF8XAoPSqPO5ws53AwFdtofdX8ftOWDVHpDlF+xiS/pjzevEYxxEwSFsGwDEkLEgTzIFXoIb1beDIhXBAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJpIHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozrCCUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4Logk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCC6UpzAIRYCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEWk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEWcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEWlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwEXIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICARgg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpwAAA==",
//                  "cHNidP8BAF4BAAAAAd69M75rD3ywxe+2W8UzI43KrrBXZxK/RnoXp8di1/KIAAAAAAD9////ASICAAAAAAAAIlEg26+CpfM2fyoA0tM8es97+DAc6b1r2Cg/9Ri84OiRbHUf5gwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3gBAwSDAAAAQRST9EizFZNv49OGEP1h8V+JPD2K+NxNuurLNQk/gn5YINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacQbt1NZmQdPZIpVjIDj+VOx5BxMK4t9yjr3gigXZ2Fzn55mL/zr7zMIizFgQ4Lwn30PgJbI8PqqmrqR5NPDgSjguDIhXBAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJpIHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozrCCUaelOYX+0Ibkpj+6w0/fpAZSLU2gDvel9p3Uv6QyV4Logk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCC6UpzAIRYCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEWk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEWcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEWlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwEXIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICARgg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpwAAA=="
//                  ];
        
//             for psbt in signed_psbts {
//                 let psbt = PartiallySignedTransaction::from_str(psbt).unwrap();
//                 base_psbt.combine(psbt).ok();
//             }
        
//             let secp = Secp256k1::new();
        

          


//             let to = Address::from_str("bc1pt5ht6yugdjqv5nhj2nllez45ec6j033setf46agmdsjn8w6kxduqcu6feh").ok().unwrap();

            
//             let mut tx_builder = wallet.wallet.build_tx().coin_selection(LargestFirstCoinSelection);
//             tx_builder
//             .ordering(TxOrdering::Untouched)
//             .add_foreign_utxo(outpoint,inpiut,100).unwrap()
//             .add_recipient(to.script_pubkey(), 1)
//             .fee_absolute(0)
//             .enable_rbf().allow_dust(true)
//             .manually_selected_only();
        

//             let (mut _psbt, _details) = tx_builder.finish().unwrap();
//             println!("psbt_user:{}",_psbt);
//             let _ = base_psbt.combine(_psbt.clone()).unwrap();
           
//             let psbt = base_psbt.finalize(&secp).unwrap();
//             let finalized_tx = psbt.extract_tx();
            
//             println!("tx:{:#?}",finalized_tx);
//             dbg!(finalized_tx.txid());
//             let broadcast = wallet.blockchain.broadcast(&finalized_tx);
//             match  broadcast {
//                 Ok(_) => {println!(" succesfullt broadcasted")},
//                 Err(err) =>{println!("error:{}",err)}
//             }
//         }
//         Err(err) => println!("{}", err),
//     }

//     let signed_psbts = vec![
//         // TODO: Paste each participant's PSBT here
//         "cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2Ioz24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxARRoVmkL+sveMsj7R6iyPXzL0Y7WDVCdM9hYlbwQKPPCToySBaPzbnsIZYO6oWyNb3+Nj9Qvc3bi91tihNdUokyIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAEBK0CcAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2Ioz24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxArTFaduuc4dzmejdmAwvScZEMosugic73uw5MTxmmsPl2LtCduF8255BJgVt6VPo/I3F1CTyDCy7453CBK+Hy/iIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEHk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEHcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEHlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwA=",
//         "cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxAizNkIn1FcBqiktX5TvOLxRk5iKQklW/jCZwQuUPniE0FQrl/M9Ry0P7MhbA+kD/imUtQ+TW80X5jXfOKeR5kISIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAEBK0CcAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxADFfsqur7pY++eW9rMNAI0AJuFtSfydNYnVq7wOQtNGL5IZGUHXDLNw4i8NH7acA87mySOTekGOuPvD6c5OW0uSIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEHk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEHcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEHlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwA="
//         ];
// }