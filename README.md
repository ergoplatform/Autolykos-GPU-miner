# Autolykos cuda-miner

## Prerequisites
(Ubuntu 16.04 or 18.04)

To compile you need the following:

1. CUDA toolkit: [installation guide](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html)
2. libcurl library:
```
$ apt install libcurl4-openssl-dev
```
3. openssl library:
```
$ apt install libssl-dev
```

## Install

1. Clone repository to '<YOUR_PATH>'
2. Change directory to '<YOUR_PATH>/autolykos/secp256k1'
3. run 'make'

If the process above completed successfully,
there will appear an executable

'<YOUR_PATH>/autolykos/secp256k1/auto.out'

## Run

You should pass a name of a configuration file '<YOUR_CONFIG_FILE>' as an argument.
The configuration file must contain json string of the following structure:

{ "seed" : "seedstring", "node" : "https://127.0.0.1", "keepPrehash" : false }

If the filename is not specified, the miner will
try to open '<YOUR_PATH>/autolykos/secp256k1/config.json' file.
You can examine a stub configuration file '<YOUR_PATH>/autolykos/secp256k1/stub.json'.

The mode of execution with 'keepPrehash' option:
1. true -- enable total unfinalized prehashes array (5GB) reusage.
2. false -- prehash recalculation for each block.

To run the miner type:
```
$ <YOUR_PATH>/autolykos/secp256k1/auto.out [YOUR_CONFIG_FILE]
```

To exit miner in foreground mode:

1. Press any key
2. Wait till 'Commencing termination' message
