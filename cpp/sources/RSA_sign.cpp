#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <memory.h>

// Generate a RSA signature

int main()
{
	RSA* key_pair = NULL;

	unsigned char sha1_message_digest[] = { 0x17, 0x1E, 0x7E, 0xBC, 0x94, 0xF1, 0x38, 0x56, 0x63, 0x68, 
											0x5F, 0xD8, 0x97, 0x9C, 0x26, 0x1B, 0xD6, 0xE5, 0x56, 0x6C };

	// get the private key (from the PEM file)
	FILE* priv_file = fopen("RSAPrivateKey.pem", "r");
	key_pair = PEM_read_RSAPrivateKey(priv_file, NULL, NULL, NULL);

	// encrypt the message digest
	int key_size = RSA_size(key_pair); // RSA key size in number of bytes
	unsigned char* signature = (unsigned char*)malloc(key_size);
	memset(signature, 0x00, key_size);
	int enc_size = RSA_private_encrypt(sizeof(sha1_message_digest), sha1_message_digest, signature, key_pair, RSA_PKCS1_PADDING);

	printf("Signature is: ");
	for (unsigned char i = 0; i < enc_size; i++)
	{
		printf("%02X", signature[i]);
	}
	printf("\n\n");

	// save the encrypted message digest into a signature file
	FILE* sig_file = fopen("RSASignature.sig", "wb+");
	fwrite(signature, sizeof(unsigned char), enc_size, sig_file);

	RSA_free(key_pair);
	free(signature);

	fclose(priv_file);
	fclose(sig_file);
	return 0;
}