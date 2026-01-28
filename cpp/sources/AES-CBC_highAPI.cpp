
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/applink.c> // REQUIRED for Windows
using namespace std;

int main()
{
	unsigned char aes_key[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x03, 0x14, 0x05, 0x36, 0x07, 0x38,
		0x11, 0x12, 0x03, 0x24, 0x05, 0x36, 0x07, 0x28,
		0x11, 0x12, 0x03, 0x34, 0x05, 0x36, 0x07, 0x1f};
	unsigned char IV[] = {
		0xf1, 0xe2, 0xd3, 0xa4, 0x05, 0x06, 0xff, 0x9f,
		0xf1, 0xe2, 0xd3, 0xa4, 0x05, 0x36, 0xff, 0x93};

	unsigned char plaintext[] = {
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
		0x01,
		0x02,
		0x03,
		0xdd,
	};

	unsigned char ciphertext[48];
	memset(ciphertext, 0x00, sizeof(ciphertext));

	EVP_CIPHER_CTX *pCtx = NULL;
	EVP_CIPHER *pCipher = NULL;

	pCtx = EVP_CIPHER_CTX_new();
	pCipher = (EVP_CIPHER *)EVP_aes_256_cbc();

	EVP_CIPHER_CTX_init(pCtx);

	EVP_EncryptInit_ex(pCtx, pCipher, NULL, aes_key, IV);
	EVP_CIPHER_CTX_set_padding(pCtx, 0);

	int key_length = EVP_CIPHER_CTX_key_length(pCtx);
	int AES_block_size = EVP_CIPHER_CTX_block_size(pCtx);
	int iv_length = EVP_CIPHER_CTX_iv_length(pCtx);
	printf("AES key length is %d bytes\n", key_length);
	printf("AES block size is %d bytes\n", AES_block_size);
	printf("AES IV length is %d bytes\n", iv_length);

	int cipher_len = 0;
	unsigned int ciphertext_length = 0;

	EVP_EncryptUpdate(pCtx, ciphertext, &cipher_len, plaintext, sizeof(plaintext));
	ciphertext_length += cipher_len;
	EVP_EncryptFinal_ex(pCtx, (unsigned char *)(ciphertext + cipher_len), &cipher_len);
	ciphertext_length += cipher_len;

	printf("AES-CBC encrypted content -> ");
	for (unsigned int i = 0; i < ciphertext_length; i++)
	{
		printf("%02x", ciphertext[i]);
	}

	printf("\n\n");

	// deallocations
	EVP_CIPHER_CTX_free(pCtx);

	return 0;
}
