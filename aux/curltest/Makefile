test:
	g++ -L/usr/local/lib -lcurl -I/usr/local/include test.c -o test.out -L./jsmn -ljsmn

curl:
	g++ -o curltest.out curltest.c

openssl:
	g++ -o osslt.out openssl_test.c -lssl -lcrypto

all: test

clean:
	rm -rf *.out
