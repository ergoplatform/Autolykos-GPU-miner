# Autolykos CUDA-miner

## Prerequisites (Linux)
(For Ubuntu 16.04 or 18.04)

To compile you need the following:

1. CUDA Toolkit: see [installation guide](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html)
2. CUDA Driver compatible with installed Toolkit: see [compatibility table](https://docs.nvidia.com/deploy/cuda-compatibility/index.html#binary-compatibility__table-toolkit-driver)
3. libcurl library: to install run
```
$ apt install libcurl4-openssl-dev
```
4. OpenSSL 1.0.2 library: to install run
```
$ apt install libssl-dev
```

## Install (Linux)

1. Change directory to `autolykos/secp256k1`
2. Run `make`

If `make` completed successfully there will appear an executable
`autolykos/secp256k1/auto.out` and (if not already present)
a config file `autolykos/secp256k1/config.json` with stub contents.

## Test (Linux)

1. Change directory to `autolykos/secp256k1`
2. Run `make test`

If `make` completed successfully there will appear a test executable
`autolykos/secp256k1/test.out`.

## Install (Windows 64-bit)

1. Install compatible pair of MS Visual Studio C++ toolchain and CUDA toolkit [compatibility table for latest CUDA toolkit](https://docs.nvidia.com/cuda/cuda-installation-guide-microsoft-windows/)
2. Build libcurl from sources with Visual Studio toolchain [instruction](https://medium.com/@chuy.max/compile-libcurl-on-windows-with-visual-studio-2017-x64-and-ssl-winssl-cff41ac7971d)
3. Download OpenSSL 1.0.2 [installer from slproweb.com](https://slproweb.com/download/Win64OpenSSL-1_0_2u.exe)
4. Edit `secp256k1/buildwin.cmd` file, change `OPENSSL_DIR`, `LIBCURL_DIR` to your libcurl and OpenSSL directories, change `CUDA_COMPUTE_ARCH` to GPU code architecture you want
5. Find `vcvars64.bat` script, it should be in `VISUAL_STUDIO_INSTALL_DIRECTORY\VC\Auxiliary\Build`
6. Run cmd.exe, run `vcvars64.bat` script, then change dir to secp256k1, then run `buildwin.cmd`
7. If everything went good, `miner.exe` should appear in `secp256k1` directory 
8. If `miner.exe` can't find `nvml.dll`, add `C:\Program Files\NVIDIA Corporation\NVSMI` to your PATH environment variable before running.


## Run (Linux)

- To run the miner you should pass a name of a configuration file `[YOUR_CONFIG]` as an optional argument
- If the filename is not specified, the miner will try to use `autolykos/secp256k1/config.json` as a config
- The configuration file must contain json string of the following structure:  
`{ "mnemonic" : "mnemonicstring", "node" : "https://127.0.0.1", "keepPrehash" : false }`

If your seed mnemonic string is protected by password, add option `"mnemonicPass": "yourpassword"` to your configuration.

The mode of execution with `keepPrehash` option:
1. `true` -- enable total unfinalized prehashes array (5GiB) reusage. ( Should only be used if your CUDA devices have >= 8GiB memory)
2. `false` -- prehash recalculation for each block. (For CUDA devices with >= 3GiB memory)

To run the miner on all available CUDA devices type:
```
$ <YOUR_PATH>/autolykos/secp256k1/auto.out [YOUR_CONFIG]
```

To choose CUDA devices change and use `runner.sh` or directly change environment variable `CUDA_VISIBLE_DEVICES`

## Run (Windows 64-bit)

- Create a config.json file in miner directory with following structure:
`{ "mnemonic" : "mnemonicstring", "node" : "https://127.0.0.1", "keepPrehash" : false }`

If your seed mnemonic string is protected by password, add option `"mnemonicPass": "yourpassword"` to your configuration.

The mode of execution with `keepPrehash` option:
1. `true` -- enable total unfinalized prehashes array (5GiB) reusage. ( Should only be used if your CUDA devices have >= 8GiB memory)
2. `false` -- prehash recalculation for each block. (For CUDA devices with >= 3GiB memory)

To change CUDA devices available to the miner change environment variable `CUDA_VISIBLE_DEVICES` , for example ` set CUDA_VISIBLE_DEVICES="0,1" `


## Mnemonic and public key generation

- Run `auto.out -G`

It will generate a BIP39 192 bit entropy mnemonic phrase and public key for you.

## Testnet public node

Sometimes mining problems can be related to your Ergo node problems. We recommend to test your miner build with this public testnet node:

`{
  "mnemonic": "noise peasant subway frozen illegal pretty oak agent train valid wash title burst column yard decide move coin gas asset pretty hire happy fuel",
  "node": "http://159.203.36.162:9052",
  "keepPrehash": true
}`

## HTTP Info

Miner has a HTTP info page located at `http://miningnode:36207` (one can change default port by adding `-DHTTPAPI_PORT XXXX` to Makefile).

It outputs total hashrate, and per-GPU hashrates, power usages and temperatures in JSON format (relies on NVML, can fail if NVML fails - if so, JSON contains error field).
