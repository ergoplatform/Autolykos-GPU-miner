SET "OPENSSL_DIR=C:\openssl102"
SET "LIBCURL_DIR=C:\Users\mam0nt\curl"
SET "CUDA_COMPUTE_ARCH=sm_35"
cd src
nvcc -o ../miner.exe -arch=%CUDA_COMPUTE_ARCH% ^
 -I %OPENSSL_DIR%\include ^
 -I %LIBCURL_DIR%\include ^
 -l %LIBCURL_DIR%\builds\libcurl-vc-x64-release-dll-ipv6-sspi-winssl-obj-lib/libcurl ^
 -l %OPENSSL_DIR%\lib\libeay32 -L %OPENSSL_DIR%/lib ^
autolykos.cu compaction.cu conversion.cu cryptography.cu definitions.cu jsmn.c ^
mining.cu prehash.cu processing.cu reduction.cu request.cu easylogging++.cc
cd ..
