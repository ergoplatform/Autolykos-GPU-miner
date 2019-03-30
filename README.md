## Prerequisites
(Ubuntu 16.04 or 18.04)

To compile you need the following:

1. CUDA toolkit
2. libcurl library:
*'$ apt install libcurl4-openssl-dev'*
3. openssl library:
*'$ apt install libssl-dev'*

---

## Install

1. Clone repository to *'<YOUR_PATH>'*
2. Change directory to *'<YOUR_PATH>/autolykos/secp256k1'*
3. run 'make'

If the process above completed successfully,
there will appear an executable

*'<YOUR_PATH>/autolykos/secp256k1/auto.out'*

---

## Run

To run the miner you should specify an optional argument -- name *'<YOUR_CONFIG_FILE>'* of a txt file containing secret key.
If a filename was not specified, the miner will try to open *'<YOUR_PATH>/autolykos/secp256k1/config'* file.
Input file must contain a string of 64 character with secret key in hexadecimal Big-Endian representation.
You can see a format of a key in a stub input file *'<YOUR_PATH>/autolykos/secp256k1/stub.config'*.

To start miner:

1. Change directory to *'<YOUR_PATH>/autolykos/secp256k1/'*
2. run *'./auto.out [YOUR_CONFIG_FILE]'*

To exit miner in foreground mode:

1. Press any key
2. Wait till 'Commencing termination' message
