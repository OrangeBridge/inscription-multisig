

use bdk::bitcoin::{Address, Network};
use bdk::bitcoincore_rpc::jsonrpc::serde_json;
use bdk::blockchain::rpc::Auth;
use bdk::blockchain::{ Blockchain, RpcBlockchain};

use bdk::wallet::AddressIndex;
use serde::{Deserialize, Serialize};

use std::clone;
use std::fs::remove_file;
use std::str::FromStr;
use std::{
    io::{BufRead, BufReader},
    process::Stdio,
    str,
};

use crate::multi_wallet::MultiWallet;
use crate::utils::{MempoolFeeRate, ParseOutput};
use crate::{brc20::Brc20, utils::executable_path};
use anyhow::{bail, Result};
use std::process::Command;

#[derive(Debug)]
pub struct OrdClient {
    auth: Auth,
    network: Network,
}
#[derive(Clone)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Inscription {
    pub id: String,
    pub location: String,
}
#[derive(Clone)]
#[derive(Serialize, Deserialize, Debug)]
pub struct InscribeOutput {
    pub commit: String,
    pub commit_psbt: Option<serde_json::Value>,
    pub inscriptions: Vec<Inscription>,
    pub parent: Option<serde_json::Value>,
    pub reveal_psbt: Option<serde_json::Value>,
    pub total_fees: u128,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RecieveOutput {
    pub address:String
}


pub(crate) trait AddArgs {
    fn add_auth(&mut self, auth: Auth);
     fn add_network_args(&mut self, network: Network);
     async fn add_fee_rate(&mut self, network: &RpcBlockchain,network:Network);
}



impl OrdClient {
    pub async fn new(auth: Auth, network: Network) -> Result<OrdClient> {
        let _status = server_online().await;
        if _status {
            let ord = OrdClient { auth, network };
            let _ = ord.init();
            return Ok(ord);
        } else {
            bail!("ord server not running");
        }
    }
    pub  fn init(&self) -> Result<()>{
        let mut args = vec![];
        args.add_auth(self.auth.clone());
        args.add_network_args(self.network);
        args.extend(["wallet".to_string(),"create".to_string()]);
        let result  = self.run(args);
        if let Ok(r) = result{
            // println!("result {}",r);
        }
        else{
        }

        Ok(())
    }

    /**
     * generate a new recieve address from ord wallet 
     */
    pub fn recieve(&self)-> Result<Address>{
        let mut args = vec![];
        args.add_auth(self.auth.clone());
        args.add_network_args(self.network);
        args.extend(["wallet".to_string(),"receive".to_string()]);
        let out = self.run(args)?;
        if let Some(recieve_output) = out.parse_output::<RecieveOutput>(){
            let _add = Address::from_str(recieve_output.address.as_str())?;
            return Ok(_add);
            
        }
        bail!("failed to generate receive Address");

    }
    /**
     * run ord commands and retuen the output
     */
    
    pub fn run(&self, args: Vec<String>) -> Result<String>{
        let output = Command::new(executable_path("ord"))
            .args(args)
            .output()
            .expect("Failed to execute command");
        let stdout = str::from_utf8(&output.stdout).unwrap_or("Error decoding stdout");
        let stderr = str::from_utf8(&output.stderr).unwrap_or("Error decoding stderr");
        if !stdout.trim().is_empty() {
            return Ok(stdout.to_string())
        }
        else if  !stderr.trim().is_empty() {
            bail!(stderr.to_string());
        }
        else{
            bail!("no output generated")
        }    
    }
    /**
     * inscribe brc20 inscription
     */
    pub async fn inscribe_brc20(&self, brc20: Brc20, to: Address, blockchain: &RpcBlockchain)->Result<InscribeOutput> {
        let mut args = vec![];
        args.add_auth(self.auth.clone());
        args.add_network_args(self.network);
        args.extend(["wallet".to_string(), "inscribe".to_string()]);
        args.add_fee_rate(blockchain,self.network).await;
        args.extend([
            "--postage".to_string(),
            "546 sats".to_string(),
            "--destination".to_string(),
            to.to_string(),
            "--file".to_string(),
        ]);

        match brc20.output_json() {
            Ok(path) => {
                args.push(path.clone());
                let out = self.run(args);
                let _ = remove_file(path);
                match out {
                    Ok(json) => {
                        if let Some(p) = json.parse_output::<InscribeOutput>(){
                            return Ok(p);
                        }
                        else {
                            bail!("failed to inscribe check logs")
                        }
                        
                      
                    },
                    Err(err) => bail!("failed to inscribe ERROR:{}",err),
                }
                
               
            }
            Err(e) => panic!("Failed to write to file: {}", e),
        };
    }
}


impl AddArgs for Vec<String> {
    fn add_auth(&mut self, auth: Auth) {
        let mut _args: Vec<String>;
        match auth {
            Auth::UserPass { username, password } => {
                _args = vec![
                    "--bitcoin-rpc-username".to_string(),
                    username.clone(),
                    "--bitcoin-rpc-password".to_string(),
                    password.clone(),
                ];
            }
            Auth::Cookie { file } => {
                _args = vec![
                    "--cookie-file".to_string(),
                    file.to_str().unwrap().to_string(),
                ];
            }
            Auth::None => todo!(),
        }
        self.extend(_args)
    }

    fn add_network_args(&mut self, network: Network) {
        match network {
            Network::Testnet => self.push("-t".to_string()),
            Network::Bitcoin => {}
            Network::Signet => self.push("-s".to_string()),
            Network::Regtest => self.push("-r".to_string()),
            _ => panic!("invalid Network"),
        }
    }

    async fn add_fee_rate(&mut self, blockchain: &RpcBlockchain,network:Network) {
        self.push("--fee-rate".to_string());
        if network == Network::Regtest{
            self.push("1".to_string())
        }
        else if network == Network::Bitcoin{
            let res = reqwest::get("https://mempool.space/api/v1/fees/recommended").await;
            match res {
                Ok(res) => {
                    if res.status().is_success() {
                        let fee = res.json::<MempoolFeeRate>().await.unwrap();
                        // println!("fee {}",fee.fastestFee);
                        self.push(fee.fastestFee.to_string());
                        return ;
                    } 
                }
                Err(_) => {}
            }
            if let Ok(fee) = blockchain.estimate_fee(1) {
                // println!("fee {}",fee.as_sat_per_vb().to_string());
                self.push(fee.as_sat_per_vb().to_string());
            } else  {
                panic!("could not estimat gas fee")
            }
        }

       
  
    }
}

pub async fn server_online() -> bool {
    let res = reqwest::get("http://127.0.0.1:80").await;
    match res {
        Ok(res) => {
            if (res.status().is_success()) {
                return true;
            } else {
                return false;
            }
        }
        Err(_) => return false,
    }
}

#[tokio::test]
async fn test_server_online() {
    let _status = server_online().await;
    assert!(_status);
}

#[tokio::test]
async fn estimate_fee(){

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
        Auth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        "https://api.hiro.so".to_string(),
        "ssl://electrum.emzy.de:50002".to_string()
    ).await;
    match  wallet {
        Ok(wallet) => {
            let mut args = vec![];
            args.add_fee_rate(&wallet.blockchain,Network::Bitcoin).await;
            print!("{:?}",args)
        }
        Err(e) => {
            print!("{} error",e)
        },
    }
        
}
   
    

#[tokio::test]
async fn inscribe_brc20_test(){
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
        "https://api.hiro.so".to_string(),
        "ssl://electrum.emzy.de:50002".to_string()
    ).await;
    match  wallet {
        Ok(wallet) => {
            if let Ok(address) = wallet.wallet.get_internal_address(AddressIndex::New) {
                println!("{} address", address);
            } else {
                print!("failed to load address")
            }
            let brc =  Brc20::new_deploy("test".to_string(), 100.00, 200.00) ;
            if let Ok(address) = wallet.wallet.get_internal_address(AddressIndex::New){
                let output = wallet.ord.inscribe_brc20(brc, address.address, &wallet.blockchain).await;
                match output {
                    Ok(ins) => {
                        println!("out {:?}",ins)
                    },
                    Err(err) => {
                        println!("error {}",err)
                    }
                }
            }else{

            }
        }
        Err(e) => {
            print!("{} error",e)
        },
    }
}



#[tokio::test] 
pub async fn get_receive(){
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
        "https://api.hiro.so".to_string(),
        "ssl://electrum.emzy.de:50002".to_string()
    ).await;
    match  wallet {
    Ok(wallet) => {
        if let Ok(address) = wallet.ord.recieve(){
            println!("address: {}",address);
        }
        else {
            panic!("failed to get address");
        }
    },
    Err(_) => panic!("failed to load wallet")
    }
        
    
}