use bdk::bitcoincore_rpc::jsonrpc::serde_json;
use bdk::bitcoin::secp256k1::rand;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{env, fs, path};
use std::io::Write;
use std::{fs::File, path::PathBuf};

use crate::utils::generate_random_file_name;


#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Brc20 {
    Brc20Op{
        p: String,
        op: String,
        tick: String,
        amt: String,  

    },
    Brc20Deploy {
        p: String,
        op: String,
        tick: String,
        max: String,
        lim: String,
    }
}
#[derive(Deserialize)]
pub struct Brc20Balance{
    pub ticker:String,
    pub available_balance:String,
    pub transferrable_balance:String,
    pub overall_balance:String,
}
#[derive(Deserialize)]
pub struct BalanceResponse{
    pub limit: u16,
    pub offset: u16,
    pub total: u16,
    pub results: Vec<Brc20Balance>
}



impl  Brc20{
    /**
     * create deploy inscription data
     */
    pub fn new_deploy(tick:String,max:f64,lim:f64)->Self{
         //@updateHere chek if valid deploy ******************** 
        Brc20::Brc20Deploy { 
            p: "brc-20".to_string(), 
            op: "deploy".to_string(), 
            tick, 
            max: max.to_string(),
            lim: lim.to_string()}
        
        }
    /**
     * create transfer inscription data
     */
    pub fn new_transfer(tick:String,amt:f64)->Self{
         //@updateHere chek if valid transfer ******************** 
        Brc20::Brc20Op { 
            p: "brc-20".to_string(), 
            op: "transfer".to_string(), 
            tick,
            amt: amt.to_string() 
        }
    }
    /**
     * create mint inscription data
     */
    pub fn new_mint(tick:String,amt:f64)->Self{
        //@updateHere chek if valid mint ******************** 
        Brc20::Brc20Op { 
            p: "brc-20".to_string(), 
            op: "mint".to_string(), tick, amt:amt.to_string()
        }
    }
    /**
     * create output file for
    */
    pub fn output_json(&self) -> std::io::Result<String> {
        let json_data = serde_json::to_string(&self).unwrap();
        let (base_name, op, tick) = match self {
            Brc20::Brc20Op { op, tick, .. } => (format!("{}_{}", op, tick), op, tick),
            Brc20::Brc20Deploy { op, tick, .. } => (format!("{}_{}", op, tick), op, tick),
        };
        let filename = generate_random_file_name(&base_name, "txt");
        let tmp_dir = env::var("TMP_DIR").unwrap_or_else(|_| "tmp".to_string());
        let path = Path::new(&tmp_dir).join(filename);
        fs::create_dir_all(&tmp_dir)?;
        fs::write(path.clone(), json_data)?;
        Ok(path.to_str().unwrap().to_string())
    }

    
}


impl Brc20Balance{
    pub fn is_available(&self,amount:f64)->bool{
        let available:f64= self.available_balance.parse().unwrap();
        if available >= amount {
            return true;
        }
        return  false;
    }
}


