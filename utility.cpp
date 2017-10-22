#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;

bool decrypt2 (unsigned char *key,
               unsigned char *iv,
               unsigned char *encryptedData,
			unsigned char *decryptedData,
               int encryptedLength,
			EVP_CIPHER_CTX *cryptCtx) {
    EVP_CIPHER_CTX_init(cryptCtx);
    int decryptedLength = 0;
    int lastDecryptLength = 0;
    if (EVP_DecryptInit_ex(cryptCtx,
        EVP_aes_256_cbc(), NULL, key, iv) == 1) {
        if(EVP_DecryptUpdate(cryptCtx, decryptedData,
            &decryptedLength, encryptedData, encryptedLength)){
            EVP_DecryptFinal_ex(cryptCtx,
                decryptedData + decryptedLength,
                &lastDecryptLength);
        }
    }
    EVP_cleanup();
	int bad = 0;
	for(int i=0;i<encryptedLength;i++){
		if (decryptedData[i] < 32 || 126 < decryptedData[i]){
			bad++;
		}
	}
	return ((4*bad) < encryptedLength);
}

char getByte(char x, char y) {
	x -= 'a' <= x ? ('a' - 10) : '0';
	y -= 'a' <= y ? ('a' - 10) : '0';
	return (x << 4) | (y & 0x0f);
}


static std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

    int val=0, valb=-8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

void readParams(char **argv, unsigned char **iv, unsigned char **key, unsigned char **cryptogram, int numOfGuess){

	// printf("%s\n", argv[3]);
	string cryptoStr(argv[1]);
	string cryptogramStr = base64_decode(cryptoStr);
	*cryptogram = (unsigned char*)malloc(100* sizeof(char) * cryptogramStr.size());
	for(int i=0;i<(int)cryptogramStr.size();i++){
		(*cryptogram)[i]=cryptogramStr[i];
	}
	for(int i=0;i<16;i++){
		(*iv)[i] = getByte(argv[2][i*2],argv[2][(i*2)+1]);
	}
	for(int i=0;i<64-numOfGuess;i++){
		// (*key)[numOfGuess + i] = getByte(argv[3][i*2],argv[3][(i*2)+1]);
		(*key)[numOfGuess + i] = argv[3][i];
	}
	// printf("%d\n", (int)decrypt2(key, iv, (unsigned char*)cryptogram.c_str(), 60));
}
