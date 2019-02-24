## Compile

To compile you need a preinstalled CUDA toolkit of latest version.

1. Clone repository to '*<YOUR_PATH>/autolykos/*'
2. Change directory to '*<YOUR_PATH>/autolykos/*'
3. run 'make'

---

## Run

To run a miner you should specify an input file.

You can find a stub input '*stub.inp*' in your '*<YOUR_PATH>/autolykos/*' directory.

1. Change directory to '*<YOUR_PATH>/autolykos/*'
2. run '*./test.out <YOUR_FILE>*'

Input file must contain numbers specified below in **hexadecimal Big-Endian** representation:

1. Four 64bit words of **b** -- puzzle boundary.
2. Four 64bit words of **m** -- message.
3. Four 64bit words of **sk** -- user secret key.
4. One 8bit word and four 64bit words of **pk** -- user public key.
5. Four 64bit words of **x** -- one time secret key.
6. One 8bit word and four 64bit words of **w** -- one time public key.

