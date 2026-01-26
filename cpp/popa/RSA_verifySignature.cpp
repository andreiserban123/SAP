#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/applink.c>
#include <memory.h>

// Verify a RSA signature

int main()
{
	RSA* key_pair = NULL;

	unsigned char sha1_message_digest[] = { 0x17, 0x1E, 0x7E, 0xBC, 0x94, 0xF1, 0x38, 0x56, 0x63, 0x68,
											0x5F, 0xD8, 0x97, 0x9C, 0x26, 0x1B, 0xD6, 0xE5, 0x56, 0x6C };

	// get the public key (from the PEM file)
	FILE* pub_file = fopen("RSAPublicKey.pem", "r");
	key_pair = PEM_read_RSAPublicKey(pub_file, NULL, NULL, NULL);

	// get the signature (from .sig file)
	int key_size = RSA_size(key_pair);
	unsigned char* signature = (unsigned char*)malloc(key_size);

	FILE* sig_file = fopen("RSASignature.sig", "rb");
	fread(signature, sizeof(unsigned char), key_size, sig_file);

	// decrypt the signature
	unsigned char* restore_message_digest = (unsigned char*)malloc(sizeof(SHA_DIGEST_LENGTH));
	int dec_size = RSA_public_decrypt(key_size, signature, restore_message_digest, key_pair, RSA_PKCS1_PADDING);

	printf("Decrypted signature (message digest) is: ");
	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		printf("%02X", restore_message_digest[i]);
	}
	printf("\n\n");

	// compare the sha1_message_digest against the decrypted signature
	if (memcmp(sha1_message_digest, restore_message_digest, SHA_DIGEST_LENGTH) == 0)
	{
		printf("Signature is valid.");
	}
	else
	{
		printf("Signature is not valid.");
	}
	printf("\n\n");

	RSA_free(key_pair);
	free(signature);

	fclose(pub_file);
	fclose(sig_file);

	return 0;
}