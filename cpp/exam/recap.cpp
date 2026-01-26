#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>


int main()
{
	FILE* pub_file = fopen("RSAKey.pem", "r");
	RSA* key_pair = PEM_read_RSAPublicKey(pub_file, NULL, NULL, NULL);
	int key_size = RSA_size(key_pair);
	unsigned char* signature = (unsigned char*)malloc(key_size);

	FILE* sig_file = fopen("signature.sig", "rb");
	fread(signature, sizeof(unsigned char), key_size, sig_file);

	unsigned char* restore_message_digest = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
	int dec_size = RSA_public_decrypt(key_size, signature, restore_message_digest, key_pair, RSA_PKCS1_PADDING);
	printf("Decrypted signature (message digest) is: ");
	for (unsigned char i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		printf("%02X", restore_message_digest[i]);
	}
	printf("\n\n");


	RSA_free(key_pair);
	free(signature);

	fclose(pub_file);
	fclose(sig_file);

	FILE* passwords_file = fopen("wordlist.txt", "r");

	unsigned char buffer[300];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char buffer2[300];
	int line = 1;
	while (fscanf(passwords_file, "%s", buffer) > 0) {

		strcpy((char*)buffer2, (char*)buffer);
		strcat((char*)buffer, "ISMsalt");
		
		SHA256(buffer, strlen((const char*)buffer), digest);
		
		if (memcmp(digest, restore_message_digest, SHA256_DIGEST_LENGTH) == 0) {
			printf("Line: %d, word: %s\n", line, buffer2);
			break;
	
		}
		line++;
	}

	unsigned char IV[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
						  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};

	
	FILE* file_word = fopen("word.enc", "wb");

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	unsigned char ciphertext[512];
	int len, ciphertext_len = 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, restore_message_digest, IV);
	EVP_EncryptUpdate(ctx, ciphertext, &len, buffer2, strlen((char*)buffer2));
	ciphertext_len += len;
	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	fwrite(ciphertext, 1, ciphertext_len, file_word);
	fclose(file_word);

	for (int i = 0; i < ciphertext_len; i++) {
		printf("%02x", ciphertext[i]);
	}
	free(restore_message_digest);
	fclose(passwords_file);
	return 0;
}
