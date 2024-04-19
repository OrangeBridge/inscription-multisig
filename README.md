# Inscription multisig

Multisig wallet libary with brc20.
non brc20-inscription un-supported.

Bitcoin core config
```json
server=1
txindex=1
# regtest =0
rpcuser=user
rpcpassword=pass
rpcallowip=127.0.0.1
# discover=0
# dns=0
# dnsseed=0
fallbackfee=0.00001
rpcthreads=8
dbcache=4096
# listen=1
# listenonion=0
rpcserialversion=1
disablewallet=0
# blocksonly=0
zmqpubhashblock=tcp://0.0.0.0:18543
```


## requirements

### ord wallet and BitcoinCore
 https://github.com/ordinals/ord


## usage
 the multiwallet struct takes arguments for     
    pub pub_keys: Vec<String>,
    pub m: u8,
    pub wallet: Wallet<Tree>,
    pub blockchain:RpcBlockchain

   
  