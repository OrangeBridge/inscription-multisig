pub mod multi_wallet;
pub mod utils;
pub mod ord_client;
pub mod brc20;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use bdk::bitcoin::{PrivateKey, PublicKey, Network};
use bdk::keys::GeneratableDefaultOptions;
use bdk::keys::GeneratedKey;
use bdk::miniscript;
pub use bdk;
pub fn generate_tap_prvkey()-> Result<PrivateKey, Box<dyn std::error::Error>>{
    let private_key: GeneratedKey<_, miniscript::Tap> = PrivateKey::generate_default()?;
    let private_key = private_key.into_key();
    println!("private key: {}", private_key);
    Ok(private_key)
 
}

pub fn get_pub_key(priv_key:PrivateKey)->PublicKey{
   let secp = Secp256k1::new();
   let public_key = PublicKey::from_private_key(&secp, &priv_key);
   println!("Public key: {}", public_key);
   public_key
}

#[test]
fn get_priv_key(){
    if let Err(err) = generate_tap_prvkey(){
        panic!("failed to gen priv ke {}",err)
    }
}

#[test]
fn test_pubkey(){
    let priv_key = PrivateKey::from_wif("L3gEF529Rq1Zg6NdWTBFX3BmveNXdAs9xjYuzuamZWgLaMhVGnh3");
    match priv_key {
        Ok(priv_key) =>{
            let pub_key = get_pub_key(priv_key);
            println!("{}", pub_key);
            assert_eq!(pub_key.to_string(),"02425ed415b1ac0a02204e79a7423c5b476bf5bd281f65f909fa12e00e1e4b5423")
        }
        Err(err) =>   panic!("failed to import private key {}",err)
    }
}