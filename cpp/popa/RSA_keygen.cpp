#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

// Generate a RSA key pair

int main()
{
	RSA *key_pair = NULL;

	// generate a RSA key pair
	key_pair = RSA_generate_key(1024, 17, NULL, NULL);

	FILE* priv_file = fopen("RSAPrivateKey.pem", "w+");
	// save RSA private key into a PEM format file
	int result = PEM_write_RSAPrivateKey(priv_file, key_pair, NULL, NULL, 0, NULL, NULL); 
	if (result != 1)
	{
		printf("Error during write the RSA private key into the file.\n");
		return 1;
	}

	FILE* pub_file = fopen("RSAPublicKey.pem", "w+");
	// save RSA public key into a PEM format file
	result = PEM_write_RSAPublicKey(pub_file, key_pair);
	if (result != 1)
	{
		printf("Error during write the RSA public key into the file.\n");
		return 1;
	}

	printf("RSA key pair has been successfully generated.\n");

	RSA_free(key_pair); // deallocation of RSA structure done by openssl

	fclose(priv_file);
	fclose(pub_file);

	return 0;
}