#ifndef DEC_H
#define DEC_H
#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

bool decrypt2 (unsigned char *key,
               unsigned char *iv,
               unsigned char *encryptedData,
               unsigned char *decryptedData,
               int encryptedLength,
			EVP_CIPHER_CTX *cryptCtx);

int readParams(char **argv,
		unsigned char **iv,
		unsigned char **key,
		unsigned char **cryptogram,
		int numOfGuess);
#endif
