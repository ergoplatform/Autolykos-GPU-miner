SET "OPENSSL_DIR=C:\openssl102"
SET "LIBCURL_DIR=C:\Users\mam0nt\curl"
SET "CUDA_COMPUTE_ARCH=sm_60"
SET "BLOCK_DIM=16"
cd src
nvcc -o ../miner.exe -arch=%CUDA_COMPUTE_ARCH% -gencode arch=compute_35,code=sm_35 -DBLOCK_DIM=%BLOCK_DIM%^
 -I %OPENSSL_DIR%\include ^
 -I %LIBCURL_DIR%\include ^
 -l %LIBCURL_DIR%\builds\libcurl-vc-x64-release-dll-ipv6-sspi-winssl-obj-lib/libcurl ^
 -l %OPENSSL_DIR%\lib\libeay32 -L %OPENSSL_DIR%/lib ^
autolykos.cu compaction.cu conversion.cc cryptography.cc definitions.cc jsmn.c ^
mining.cu prehash.cu processing.cc reduction.cu request.cc easylogging++.cc
cd ..