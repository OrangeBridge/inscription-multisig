use anyhow::{bail, Error, Result};
use bdk::bitcoin::blockdata::witness;
use bdk::bitcoin::hashes::hex;
use bdk::bitcoin::hashes::sha256d::Hash;
use bdk::bitcoin::policy::get_virtual_tx_size;
use bdk::bitcoin::psbt::{self, Input, PartiallySignedTransaction, Psbt, PsbtSighashType};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Address, EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, Script, SigHashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
use bdk::bitcoincore_rpc::json::Utxo;
use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcSyncParams};
use bdk::blockchain::{Blockchain, ElectrumBlockchain, GetTx, RpcConfig};
use bdk::database::{Database, MemoryDatabase};
use bdk::miniscript::descriptor::TapTree;
use bdk::miniscript::policy::Concrete;
use bdk::miniscript::psbt::PsbtExt;
use bdk::miniscript::{Descriptor, ToPublicKey};

use bdk::psbt::PsbtUtils;
use bdk::signer::{InputSigner, SignerContext, SignerOrdering, SignerWrapper};
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
            // let client = electrum_client::Client::new(&electrum_rpc)?;
            // let blockchain_e = ElectrumBlockchain::from(client);
            wallet.sync(&blockchain, bdk::SyncOptions ::default())?;
        }
        else{
            wallet.sync(&blockchain, bdk::SyncOptions {
                 progress: None })?;
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
    pub async fn transfer_insc_with_witness_fee(&self,inscription:Inscription,to:Address,fee_utxos:Vec<FeeUtxo>,pub_key:PublicKey)->Result<(Psbt, TransactionDetails)> {
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
        .manually_selected_only();
        let (mut psbt, _details) = tx_builder.clone().finish()?;
        let size = psbt.extract_tx().size();     
        let (fee_utxos,fee,covered) = select_fee_utxo(fee_utxos, size, fee_rate)?;
        for utxo in fee_utxos{
            let mut input = Input::default();
            input.witness_utxo = Some(utxo.tx_out);
            let x_pub = pub_key.to_x_only_pubkey();
            input.tap_internal_key = Some(x_pub);
            tx_builder.add_foreign_utxo(utxo.outpoint, input,100)?;

        }
        if(covered> fee){
            tx_builder.add_recipient(to.script_pubkey(), covered-fee).fee_absolute(fee);
        }
        println!("covered:{} fee:{}",covered,fee);
        let (mut psbt, _details) = tx_builder.finish()?;
        Ok((psbt, _details))
    }
    pub async fn transfer_insc_with_non_witness_fee(&self,inscription:Inscription,to:Address,fee_utxos:Vec<FeeUtxo>)->Result<(Psbt, TransactionDetails)> {
        let wallet_policy = self.wallet.policies(KeychainKind::External)?.unwrap();
        let feeRate = self.fee_rate_sat_vb().await?;
        let mut path = BTreeMap::new();
        path.insert(wallet_policy.id, vec![1]);

        let fee_rate = self.fee_rate_sat_vb().await?;

        let mut tx_builder = self.wallet.build_tx().coin_selection(LargestFirstCoinSelection);
        let _ = self.sync();

       
        let utxo: LocalUtxo = self.get_utxo(inscription.location)?;
        let tx = self.blockchain.get_tx(&utxo.outpoint.txid)?.ok_or( Error::msg("failed to fetch tx"))?;
        
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
            input.non_witness_utxo = Some(tx.clone());

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
            return Ok(10.0);
        }
        else if network == Network::Bitcoin{
            let res = reqwest::get("https://mempool.space/api/v1/fees/recommended").await;
            match res {
                Ok(res) => {
                    if res.status().is_success() {
                        let fee = res.json::<MempoolFeeRate>().await?;
                        return Ok(fee.fastestFee +5.0);
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
            "022a901525c907899a43c101cc21c11cc03e1f122e7e6845303e98e73dfc73cd71".to_string(),
            "0384ed0788ee7d463d7e3c9f05761da775518d3262f2a54bcca38c9b85cd1b4a7c".to_string(),
            "0392baf3c3dc1be2993230f7eaa5742b3b5c38b2a6723750bdb6ae15ee7a859eeb".to_string()  
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
//#[tokio::test]
// async fn xfer_insc_psbt(){
//     let wallet = MultiWallet::new(
//         2,
//         vec![
//             "022a901525c907899a43c101cc21c11cc03e1f122e7e6845303e98e73dfc73cd71".to_string(),
//             "0384ed0788ee7d463d7e3c9f05761da775518d3262f2a54bcca38c9b85cd1b4a7c".to_string(),
//             "0392baf3c3dc1be2993230f7eaa5742b3b5c38b2a6723750bdb6ae15ee7a859eeb".to_string()          
//         ],
//         "./wallet_test".to_string(),
//         Network::Regtest,
//         "http://127.0.0.1:18443".to_string(),
//         Auth::UserPass {
//             username: "user".to_string(),
//             password: "pass".to_string(),
//         },
//         "https://api.hiro.so".to_string()
//     ).await;
//     match wallet {
//         Ok(mut wallet) => {
//             let ins = Inscription{
//                 id:"bf568aab915f45de604bc55c92c8665298bb8a82204fee1678e9cd3fe41bb7bdi0".to_string(),
//                 location:"bf568aab915f45de604bc55c92c8665298bb8a82204fee1678e9cd3fe41bb7bd:0:0".to_string()
//             };
//             let to = Address::from_str("bcrt1plcggswcj4zw6t3gsgef5npcvejklw505mn0e87ajxgamksuz07aqg8qt9v").ok().unwrap();
            
//             let tx_out = TxOut{
//                 value:399846, script_pubkey: 
//                 Script::from_str("5120fe10883b12a89da5c510465349870cccadf751f4dcdf93fbb2323bbb43827fba").unwrap()
//             };
//             let txid: Txid = Txid::from_str("eae5de65dc0d152600b94885701f769975947d8f18bbd9138acc9727af1d6047").unwrap();
//             let outpoint= OutPoint::new(txid, 1);


//             let fee1 = FeeUtxo{
//                 outpoint:outpoint,
//                 tx_out:tx_out,
//                 weight:100
//             };
//             let psbt = wallet.transfer_insc_with_witness_fee(ins,to,vec![fee1]).await;
//             match  psbt {
//                 Ok(psbt) => {
//                     println!("psbt:{}",psbt.0);  
//                     let tx = psbt.0.clone().extract_tx();
//                     println!("tx:{:#?}",tx);
//                     let fee = psbt.0.fee_rate().unwrap();
                    
//                     println!("feeRate:{}",fee.as_sat_per_vb());
//                 },
//                 Err(err) => {
//                     println!("error:{}",err)
//                 },
//             }
//         }
//         Err(err) => println!("{}", err),
//     }
// }

// #[tokio::test]
// async fn sign_psbt(){
//     let wallet = MultiWallet::new(
//         2,
//         vec![
//             "022a901525c907899a43c101cc21c11cc03e1f122e7e6845303e98e73dfc73cd71".to_string(),
//             "0384ed0788ee7d463d7e3c9f05761da775518d3262f2a54bcca38c9b85cd1b4a7c".to_string(),
//             "0392baf3c3dc1be2993230f7eaa5742b3b5c38b2a6723750bdb6ae15ee7a859eeb".to_string()
//         ],
//         "./wallet_test".to_string(),
//         Network::Regtest,
//         "http://127.0.0.1:18443".to_string(),
//         Auth::UserPass {
//             username: "user".to_string(),
//             password: "pass".to_string(),
//         },
//         "https://api.hiro.so".to_string()
//     ).await;
//     match wallet {
//         Ok(mut wallet) => {
//                let mut _psbt = PartiallySignedTransaction::from_str("cHNidP8BALIBAAAAAr23G+Q/zel4Fu5PIIKKu5hSZsiSXMVLYN5FX5Grila/AAAAAAD9////R2AdryeXzIoT2bsYj32UdZl2H3CFSLkAJhUN3GXe5eoBAAAAAP3///8CIgIAAAAAAAAiUSD+EIg7EqidpcUQRlNJhwzMrfdR9Nzfk/uyMju7Q4J/ulISBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7rAAgAAAAEBKyICAAAAAAAAIlEgwS3cH/F69X4lvdv1ruLtjl/BES7LR1v+AxXuZyOkknwiFcACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmkgKpAVJckHiZpDwQHMIcEcwD4fEi5+aEUwPpjnPfxzzXGsIITtB4jufUY9fjyfBXYdp3VRjTJi8qVLzKOMm4XNG0p8uiCSuvPD3BvimTIw9+qldCs7XDiypnI3UL22rhXueoWe67pSnMAhFgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIRYqkBUlyQeJmkPBAcwhwRzAPh8SLn5oRTA+mOc9/HPNcSUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PiGVEKcIRaE7QeI7n1GPX48nwV2Had1UY0yYvKlS8yjjJuFzRtKfCUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0Pj5F0LGIRaSuvPD3BvimTIw9+qldCs7XDiypnI3UL22rhXueoWe6yUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PjhBtxBARcgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBGCDc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+AABASvmGQYAAAAAACJRIP4QiDsSqJ2lxRBGU0mHDMyt91H03N+T+7IyO7tDgn+6AAAA").unwrap();
//                let private_key = PrivateKey::from_str("L11nWVMfXE5txy2zzc1T9ieR8kh2VoWVTmTVV3hvKLBgm4RXNhyV").ok().unwrap();
//                let signer = SignerWrapper::new(private_key, SignerContext::Tap { is_internal_key: true });
//                let secp = Secp256k1::new();
             
             
//             //    wallet.wallet.add_signer(
//             //         KeychainKind::External,
//             //         SignerOrdering(0),
//             //         Arc::new(signer)
//             // );
//                let mut options = SignOptions::default();
//                options.allow_all_sighashes =true;
//                options.trust_witness_utxo = true;
//                 let fin = signer.sign_input(&mut _psbt, 1, &options, &secp).unwrap();
//                 let finalized = wallet.wallet.sign(&mut _psbt, options).unwrap();
//                println!(" status:{} psbt_signed:{}", finalized,_psbt);
//         }
//         Err(err) => println!("{}", err),
//     }
// }

// #[tokio::test]
// async fn combine_broadcast(){
//     let wallet = MultiWallet::new(
//         2,
//         vec![
//             "022a901525c907899a43c101cc21c11cc03e1f122e7e6845303e98e73dfc73cd71".to_string(),
//             "0384ed0788ee7d463d7e3c9f05761da775518d3262f2a54bcca38c9b85cd1b4a7c".to_string(),
//             "0392baf3c3dc1be2993230f7eaa5742b3b5c38b2a6723750bdb6ae15ee7a859eeb".to_string()
//         ],
//         "./wallet_test".to_string(),
//         Network::Regtest,
//         "http://127.0.0.1:18443".to_string(),
//         Auth::UserPass {
//             username: "user".to_string(),
//             password: "pass".to_string(),
//         },
//         "https://api.hiro.so".to_string()
//     ).await;
//     match wallet {
//         Ok(wallet) => {
//             let mut base_psbt = PartiallySignedTransaction::from_str("cHNidP8BALIBAAAAAr23G+Q/zel4Fu5PIIKKu5hSZsiSXMVLYN5FX5Grila/AAAAAAD9////R2AdryeXzIoT2bsYj32UdZl2H3CFSLkAJhUN3GXe5eoBAAAAAP3///8CIgIAAAAAAAAiUSD+EIg7EqidpcUQRlNJhwzMrfdR9Nzfk/uyMju7Q4J/ulISBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7rAAgAAAAEBKyICAAAAAAAAIlEgwS3cH/F69X4lvdv1ruLtjl/BES7LR1v+AxXuZyOkknwiFcACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmkgKpAVJckHiZpDwQHMIcEcwD4fEi5+aEUwPpjnPfxzzXGsIITtB4jufUY9fjyfBXYdp3VRjTJi8qVLzKOMm4XNG0p8uiCSuvPD3BvimTIw9+qldCs7XDiypnI3UL22rhXueoWe67pSnMAhFgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIRYqkBUlyQeJmkPBAcwhwRzAPh8SLn5oRTA+mOc9/HPNcSUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PiGVEKcIRaE7QeI7n1GPX48nwV2Had1UY0yYvKlS8yjjJuFzRtKfCUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0Pj5F0LGIRaSuvPD3BvimTIw9+qldCs7XDiypnI3UL22rhXueoWe6yUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PjhBtxBARcgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBGCDc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+AABASvmGQYAAAAAACJRIP4QiDsSqJ2lxRBGU0mHDMyt91H03N+T+7IyO7tDgn+6AAAA").unwrap();
//             let signed_psbts = vec![
//                  // TODO: Paste each participant's PSBT here
//                  "cHNidP8BALIBAAAAAr23G+Q/zel4Fu5PIIKKu5hSZsiSXMVLYN5FX5Grila/AAAAAAD9////R2AdryeXzIoT2bsYj32UdZl2H3CFSLkAJhUN3GXe5eoBAAAAAP3///8CIgIAAAAAAAAiUSD+EIg7EqidpcUQRlNJhwzMrfdR9Nzfk/uyMju7Q4J/ulISBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7rAAgAAAAEBKyICAAAAAAAAIlEgwS3cH/F69X4lvdv1ruLtjl/BES7LR1v+AxXuZyOkknxBFCqQFSXJB4maQ8EBzCHBHMA+HxIufmhFMD6Y5z38c81x3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PhA/dZj/iN0mYbvNqCP5KXf1h7p2rRNTVBijJm+qnr4mapICasuaofZrXn7ZwKQXfbaZEIXYqHtrygb2YTT0/1KZiIVwAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSAqkBUlyQeJmkPBAcwhwRzAPh8SLn5oRTA+mOc9/HPNcawghO0HiO59Rj1+PJ8Fdh2ndVGNMmLypUvMo4ybhc0bSny6IJK688PcG+KZMjD36qV0KztcOLKmcjdQvbauFe56hZ7rulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFiqQFSXJB4maQ8EBzCHBHMA+HxIufmhFMD6Y5z38c81xJQHc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+IZUQpwhFoTtB4jufUY9fjyfBXYdp3VRjTJi8qVLzKOMm4XNG0p8JQHc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+PkXQsYhFpK688PcG+KZMjD36qV0KztcOLKmcjdQvbauFe56hZ7rJQHc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+OEG3EEBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINztfWFK+gDslkDWqTl4If7cunoppLP3XbuxxvL5V9D4AAEBK+YZBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7oAAAA=",
//                  "cHNidP8BALIBAAAAAr23G+Q/zel4Fu5PIIKKu5hSZsiSXMVLYN5FX5Grila/AAAAAAD9////R2AdryeXzIoT2bsYj32UdZl2H3CFSLkAJhUN3GXe5eoBAAAAAP3///8CIgIAAAAAAAAiUSD+EIg7EqidpcUQRlNJhwzMrfdR9Nzfk/uyMju7Q4J/ulISBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7rAAgAAAAEBKyICAAAAAAAAIlEgwS3cH/F69X4lvdv1ruLtjl/BES7LR1v+AxXuZyOkknxBFITtB4jufUY9fjyfBXYdp3VRjTJi8qVLzKOMm4XNG0p83O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PhAg+sa0ZvTAJEnTJPzGTMD9Wc7y0CCwMAYPfiwfK773oKQjllUgy32hRE77ebswhiQ24xox/NeLMFvGS6j5rp/WCIVwAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSAqkBUlyQeJmkPBAcwhwRzAPh8SLn5oRTA+mOc9/HPNcawghO0HiO59Rj1+PJ8Fdh2ndVGNMmLypUvMo4ybhc0bSny6IJK688PcG+KZMjD36qV0KztcOLKmcjdQvbauFe56hZ7rulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFiqQFSXJB4maQ8EBzCHBHMA+HxIufmhFMD6Y5z38c81xJQHc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+IZUQpwhFoTtB4jufUY9fjyfBXYdp3VRjTJi8qVLzKOMm4XNG0p8JQHc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+PkXQsYhFpK688PcG+KZMjD36qV0KztcOLKmcjdQvbauFe56hZ7rJQHc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+OEG3EEBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINztfWFK+gDslkDWqTl4If7cunoppLP3XbuxxvL5V9D4AAEBK+YZBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7oAAAA=",
//                  "cHNidP8BALIBAAAAAr23G+Q/zel4Fu5PIIKKu5hSZsiSXMVLYN5FX5Grila/AAAAAAD9////R2AdryeXzIoT2bsYj32UdZl2H3CFSLkAJhUN3GXe5eoBAAAAAP3///8CIgIAAAAAAAAiUSD+EIg7EqidpcUQRlNJhwzMrfdR9Nzfk/uyMju7Q4J/ulISBgAAAAAAIlEg/hCIOxKonaXFEEZTSYcMzK33UfTc35P7sjI7u0OCf7rAAgAAAAEBKyICAAAAAAAAIlEgwS3cH/F69X4lvdv1ruLtjl/BES7LR1v+AxXuZyOkknwiFcACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmkgKpAVJckHiZpDwQHMIcEcwD4fEi5+aEUwPpjnPfxzzXGsIITtB4jufUY9fjyfBXYdp3VRjTJi8qVLzKOMm4XNG0p8uiCSuvPD3BvimTIw9+qldCs7XDiypnI3UL22rhXueoWe67pSnMAhFgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBQBRgU8QIRYqkBUlyQeJmkPBAcwhwRzAPh8SLn5oRTA+mOc9/HPNcSUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PiGVEKcIRaE7QeI7n1GPX48nwV2Had1UY0yYvKlS8yjjJuFzRtKfCUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0Pj5F0LGIRaSuvPD3BvimTIw9+qldCs7XDiypnI3UL22rhXueoWe6yUB3O19YUr6AOyWQNapOXgh/ty6eimks/ddu7HG8vlX0PjhBtxBARcgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBGCDc7X1hSvoA7JZA1qk5eCH+3Lp6KaSz9127scby+VfQ+AABASvmGQYAAAAAACJRIP4QiDsSqJ2lxRBGU0mHDMyt91H03N+T+7IyO7tDgn+6ARNAbMnwLFYdMn3X9deGRwM8XhuQIV5NDZ0fOkPSWmOc5RwZy0TOS5c7nh9KtJYZVLCuJk5t2yf2oWaFw+JvpQM0dAAAAA=="
//                  ];
        
//             for psbt in signed_psbts {
//                 let psbt = PartiallySignedTransaction::from_str(psbt).unwrap();
//                 base_psbt.combine(psbt).ok();
//             }

//             let secp = Secp256k1::new();
//             let psbt = base_psbt.finalize(&secp).unwrap();
//             let finalized_tx = psbt.extract_tx();
//             dbg!(finalized_tx.txid());
//             let broadcast = wallet.blockchain.broadcast(&finalized_tx);
//             match  broadcast {
//                 Ok(_) => {println!(" succesfullt broadcasted")},
//                 Err(err) =>{println!("error:{}",err)}
//             }
//         }
//         Err(err) => println!("{}", err),
//     }

// }

#[tokio::test]
async fn test(){
    let wallet = MultiWallet::new(
        2,
        vec![
            "037032d63a356a821804b204bc6fb6f768e160fefb36888edad296ab9f0ad88a33".to_string(),
            "029469e94e617fb421b9298feeb0d3f7e901948b536803bde97da7752fe90c95e0".to_string(),
            "0393f448b315936fe3d38610fd61f15f893c3d8af8dc4dbaeacb35093f827e5820".to_string(),
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
            
            let mut base_psbt = PartiallySignedTransaction::from_str("cHNidP8BAP21AQIAAAAFy0pEXgOgnMqPaONq0dxWW26eBxCgeuQ1/F+otCGGu5QFAAAAAP/////LSkReA6Ccyo9o42rR3FZbbp4HEKB65DX8X6i0IYa7lAYAAAAA/////0QLI4/kA6/92xZx+G9iq1PEa5KCFHlZh2p9NNwg9kFVAAAAAAD/////BG7Hizoit6pRdS0Z9QZki4Vv/SGRA2gcugYGruPc6qUBAAAAAP/////LSkReA6Ccyo9o42rR3FZbbp4HEKB65DX8X6i0IYa7lAAAAAAA/////wZYAgAAAAAAABYAFPkFfBviIP5q9JreALkjF3jkXZb+IgIAAAAAAAAiUSCuygoGpuWFFt8h+M0JxJJfXmT974oRyXcdQKzAzUpvACDLAAAAAAAAIlEgJfMniH5NSVOgYJs4inBBjA2gAsW4PQ7w3yktazO7l+cQfQkAAAAAACJRIK7KCgam5YUW3yH4zQnEkl9eZP3vihHJdx1ArMDNSm8ALAEAAAAAAAAWABT5BXwb4iD+avSa3gC5Ixd45F2W/iwBAAAAAAAAFgAU+QV8G+Ig/mr0mt4AuSMXeORdlv4AAAAAAAEBHywBAAAAAAAAFgAU+QV8G+Ig/mr0mt4AuSMXeORdlv4AAQEfLAEAAAAAAAAWABT5BXwb4iD+avSa3gC5Ixd45F2W/gABASsiAgAAAAAAACJRICXzJ4h+TUlToGCbOIpwQYwNoALFuD0O8N8pLWszu5fnAQMEgwAAAAEXIOMDaPlD4TljY/4lqusTGjkVE0yKxGq1xMGAlVtEWQvMAAEBKxh+CgAAAAAAIlEgrsoKBqblhRbfIfjNCcSSX15k/e+KEcl3HUCswM1KbwABFyBASZNmhwY/1ISJ1WKAy36Ow+sVYAatxNLd65K0p0qjUwABAR9YAgAAAAAAABYAFPkFfBviIP5q9JreALkjF3jkXZb+AAAAAAAAAA==").unwrap();
           let script = Address::from_str("bc1p4m9q5p4xukz3dheplrxsn3yjta0xfl003ggujacagzkvpn22duqqyjan4s").unwrap().script_pubkey();
            let secp = Secp256k1::new();
            // let psbt = base_psbt.finalize(&secp).unwrap();
            // let finalized_tx = base_psbt.extract_tx();
            println!("tx:{:#?}",base_psbt.inputs[3]);
            // dbg!(finalized_tx.txid());
            // let broadcast = wallet.blockchain.broadcast(&finalized_tx);
            // match  broadcast {
            //     Ok(_) => {println!(" succesfullt broadcasted")},
            //     Err(err) =>{println!("error:{}",err)}
            // }
        }
        Err(err) => println!("{}", err),
    }

    let signed_psbts = vec![
        // TODO: Paste each participant's PSBT here
        "cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2Ioz24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxARRoVmkL+sveMsj7R6iyPXzL0Y7WDVCdM9hYlbwQKPPCToySBaPzbnsIZYO6oWyNb3+Nj9Qvc3bi91tihNdUokyIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAEBK0CcAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFHAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2Ioz24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxArTFaduuc4dzmejdmAwvScZEMosugic73uw5MTxmmsPl2LtCduF8255BJgVt6VPo/I3F1CTyDCy7453CBK+Hy/iIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEHk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEHcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEHlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwA=",
        "cHNidP8BALIBAAAAAq45l4nA4Qe2x8B1SX2eKp8Ts6NzqifjqyiRtlK3XusCAAAAAAD9////E/HtvqOBA2ze26fqhMhDUZOM44+g/wQv96HyHCflv1kAAAAAAP3///8CIgIAAAAAAAAiUSAqe8lHHxXR9lH3ewB6YpZpzBiRvkHe3DSwYFxUeYfwZQObAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3j40wwAAAEBKyICAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxAizNkIn1FcBqiktX5TvOLxRk5iKQklW/jCZwQuUPniE0FQrl/M9Ry0P7MhbA+kD/imUtQ+TW80X5jXfOKeR5kISIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAEBK0CcAAAAAAAAIlEgXS69E4hsgMpO8lT//Iq0zjUnxjDK0111G2wlM7tWM3hBFJRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXg24QjbndrGwc/1V/9+yJTNf+LWTWUWkraHgGx7v0RlpxADFfsqur7pY++eW9rMNAI0AJuFtSfydNYnVq7wOQtNGL5IZGUHXDLNw4i8NH7acA87mySOTekGOuPvD6c5OW0uSIVwQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICaSBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcwCEWAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAFGBTxAhFpP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnDgepeEhFnAy1jo1aoIYBLIEvG+292jhYP77NoiO2tKWq58K2IozJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnBzpFUMhFpRp6U5hf7QhuSmP7rDT9+kBlItTaAO96X2ndS/pDJXgJQHbhCNud2sbBz/VX/37IlM1/4tZNZRaStoeAbHu/RGWnNi3aHcBFyACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEYINuEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacAAABBSACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEGawDAaCBwMtY6NWqCGASyBLxvtvdo4WD++zaIjtrSlqufCtiKM6wglGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleC6IJP0SLMVk2/j04YQ/WHxX4k8PYr43E266ss1CT+CflggulKcIQcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUAUYFPECEHk/RIsxWTb+PThhD9YfFfiTw9ivjcTbrqyzUJP4J+WCAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacOB6l4SEHcDLWOjVqghgEsgS8b7b3aOFg/vs2iI7a0parnwrYijMlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZacHOkVQyEHlGnpTmF/tCG5KY/usNP36QGUi1NoA73pfad1L+kMleAlAduEI253axsHP9Vf/fsiUzX/i1k1lFpK2h4Bse79EZac2LdodwA="
        ];
}