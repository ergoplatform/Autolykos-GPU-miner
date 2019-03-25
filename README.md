## Prerequisites

To compile you need the following

1. CUDA toolkit
2. libcurl library
3. openssl library

## Compile

1. Clone repository to *'<YOUR_PATH>'*
2. Change directory to *'<YOUR_PATH>/autolykos/secp256k1'*
3. run 'make'

If the process above completed successfully,
there will appear an executable

*'<YOUR_PATH>/autolykos/secp256k1/auto.out'*

---

## Run

To run a miner you should specify an name *'<YOUR_KEY_FILE>'* of txt file with secret key.
Input file must contain four 64-bit words of secret key in **hexadecimal Big-Endian** representation.
You can find a stub input file *'stub.inp'* in *'<YOUR_PATH>/autolykos/secp256k1'* directory.

To start miner:

1. Change directory to *'<YOUR_PATH>/autolykos/secp256k1/'*
2. run *'./auto.out <YOUR_KEY_FILE>'*

To exit miner:

1. Press 'e'
2. Press 'Enter'