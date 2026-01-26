#include <openssl/evp.h>
#include <openssl/rsa.h>

int main()
{
	unsigned char digest[] = {
		0x01, 0x02, 0x03, 0x04, 0x05,
		0x11, 0x12, 0x13, 0x44, 0x55,
		0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
		0x21, 0x22, 0x13, 0x34, 0x45,
	};
	EVP_PKEY_CTX* pCtx = NULL;
	pCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(pCtx);
	EVP_PKEY_CTX_set_rsa_keygen_bits(pCtx, 2048);

	EVP_PKEY* pKey = NULL;
	// generate RSA key pair
	EVP_PKEY_keygen(pCtx, &pKey);

	// generate RSA signature
	unsigned int sig_length = 0;

	// preparing the call to sign
	EVP_PKEY_CTX* pSignCtx = NULL;
	pSignCtx = EVP_PKEY_CTX_new(pKey, NULL);
	EVP_PKEY_sign_init(pSignCtx);
	EVP_PKEY_CTX_set_rsa_padding(pSignCtx, RSA_PKCS1_PADDING);
	EVP_PKEY_CTX_set_signature_md(pSignCtx, EVP_sha1());

	// call #1 to get the signature length in order to perform heap allocation later
	EVP_PKEY_sign(pSignCtx, NULL, &sig_length, digest, sizeof(digest));
	unsigned char *signature = NULL;
	signature = (unsigned char*)OPENSSL_malloc(sig_length);
	// call #2 to fill the signature bytes into signature buffer
	EVP_PKEY_sign(pSignCtx, signature, &sig_length, digest, sizeof(digest));

	printf("RSA signature is -> ");
	for (unsigned int i = 0; i < sig_length; i++)
	{
		printf("%02x", signature[i]);
	}
	printf("\n\n");

	// preparing the signature verification
	EVP_PKEY_CTX* pCheckCtx = NULL;
	pCheckCtx = EVP_PKEY_CTX_new(pKey, NULL);
	EVP_PKEY_verify_init(pCheckCtx);
	EVP_PKEY_CTX_set_rsa_padding(pCheckCtx, RSA_PKCS1_PADDING);
	EVP_PKEY_CTX_set_signature_md(pCheckCtx, EVP_sha1());

	// verify RSA signature
	// signature[0] = 0xaa; // to make a wrong signature
	int result = EVP_PKEY_verify(pCheckCtx, signature, sig_length, digest, sizeof(digest));
	if (result == 1)
	{
		printf("RSA signature is valid!\n");
	}
	else
	{
		printf("RSA signature has not been validated!\n");
	}

	// deallocations
	OPENSSL_free(signature);
	EVP_PKEY_CTX_free(pCtx);
	EVP_PKEY_CTX_free(pSignCtx);
	EVP_PKEY_CTX_free(pCheckCtx);
	EVP_PKEY_free(pKey);
	return 0;
}