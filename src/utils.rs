use std::io;
use std::net::TcpStream;
use std::str;
use std::time::Duration;
use std::{path::PathBuf, process::Command};
extern  crate ping;
use bdk::bitcoin::secp256k1::rand::distributions::Alphanumeric;
use bdk::bitcoin::secp256k1::rand::{self, random, Rng};
use bdk::bitcoincore_rpc::jsonrpc::serde_json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};


const RANDOM_CHARS_LENGTH: usize = 10;

pub(crate) fn executable_path(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    if name == "ord" {
        path.pop();
        path.pop();
    }
    let exe = String::from(name) + std::env::consts::EXE_SUFFIX;
    path.push(exe);
    path
}


pub(crate) fn generate_random_file_name(base_name: &str, extension: &str) -> String {
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(RANDOM_CHARS_LENGTH)
        .map(char::from)
        .collect();
    format!("{}-{}.{}", base_name, rand_string, extension)
}


pub(crate) trait ParseOutput {
    fn parse_output<T: DeserializeOwned>(&self) -> Option<T>;
}

impl ParseOutput for &str {
    fn parse_output<T: DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_str(&self).ok()
    }
}
impl ParseOutput for String {
    fn parse_output<T: DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_str(&self).ok()
    }
}

// refacot later to more appropiate file location
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct MempoolFeeRate{
  pub fastestFee: f32,
  pub halfHourFee: f32,
  pub hourFee: f32,
  pub economyFee: f32,
  pub minimumFee: f32
}