#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <thread>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "utility.h"
using namespace std;
const int THREADS = 4;
const int LENGTH_FOR_TESTS = 50;
int CHARS = 0;
unsigned char *str[THREADS];
unsigned char *iv, *key, *cryptogram;

void fThread(int number, long long from, long long to, bool print){

	printf("started %d (%lld - %lld), %lld\n", number, from, to, (to - from));
	unsigned char *key = (unsigned char*)malloc(32*sizeof(char));
	int allocateSize = 10 * LENGTH_FOR_TESTS * sizeof(char);
	unsigned char *decryptedData = (unsigned char *) malloc (allocateSize);
	EVP_CIPHER_CTX *cryptCtx = EVP_CIPHER_CTX_new();
	int decryptedLength, lastDecryptLength;
	for(int i=0;i<32;i++){
		key[i] = 
			((str[number][i*2] - ('a' <= str[number][i*2] ? ('a' - 10) : '0'))<<4) |
			((str[number][(i*2)+1] - ('a' <= str[number][(i*2)+1] ? ('a' - 10) : '0'))&0xf);
	}

	EVP_CIPHER_CTX_init(cryptCtx);
	int good;
	int j;
	for(long long int i = from; i < to; i++){
		for(j = 0; j < CHARS; j++){
			key[j/2] &= 0xf<<((j&1)<<2);
			key[j/2] |= (i>>(j*4) & 0xf) <<(((j&1)^1) << 2);
		}
		if(print){
			printf("a");
		}
		continue;
		decryptedLength = 0;
		lastDecryptLength = 0;
		if (EVP_DecryptInit_ex(cryptCtx, EVP_aes_256_cbc(), NULL, key, iv) == 1) {
			if(EVP_DecryptUpdate(cryptCtx, decryptedData, &decryptedLength, cryptogram, LENGTH_FOR_TESTS)){
				EVP_DecryptFinal_ex(cryptCtx,	decryptedData + decryptedLength, &lastDecryptLength);
			}
		}
		EVP_cleanup();
		for(good = 0, j=0;j<LENGTH_FOR_TESTS;j++){
			if (((decryptedData[j]|0x20) >='a' && 'z'>=(decryptedData[j]|0x20))
					|| decryptedData[j]==' '
					|| decryptedData[j]=='.'
					|| decryptedData[j]==','
					){
				good++;
			}
		}
		if(good * 100 > LENGTH_FOR_TESTS * 70) {
			printf("%d) %lld %d\n", number, i, good);
			printf("%5s\n", decryptedData);
			for(int k=0;k<32;k++){
				printf("%02x", key[k]);
			}
			printf("\n");
		}
	}
	free(decryptedData);
	free(key);
	EVP_CIPHER_CTX_free(cryptCtx);
	printf("finish %d\n", number);
}
int main(int argc, char **argv) {
	iv = (unsigned char*)malloc(sizeof(char) *16);
	key = (unsigned char*)malloc(sizeof(char) *64);
	for(int i=0;i<64;i++)key[i]='\x00';
	CHARS = std::stoi(string(argv[4]));

	readParams(argv, &iv, &key, &cryptogram, CHARS);

	for(int i = 0; i < THREADS; i++){
		str[i] = (unsigned char*)malloc((64) * sizeof(char));
		for(int j = 0; j < 64; j++) {
			str[i][j] = key[j];
		}
	}
	long long max = 2L << ((CHARS * 4) - 1); //4294967296;
	long long from, to;

	thread *threads[THREADS];

	for(int i = 0; i < THREADS; i++){
		from = i * (max / THREADS);
		to = (i + 1) * (max / THREADS);
		if(i == THREADS - 1){
			to = max;
		}
		threads[i] = new thread (fThread, i, from, to, argc > 10);     // spawn new thread that calls foo()
	}

	for(int i = 0; i < THREADS; i++){
		threads[i]->join();
	}
	for(int i = 0; i < THREADS; i++){
		free(str[i]);
	}

	free(key);
	free(cryptogram);
	free(iv);
	return 0;
}
