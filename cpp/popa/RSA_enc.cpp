#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <memory.h>

// Verify a RSA signature

int main(int argc, char* argv[])
{
	if (argc == 4)
	{
		RSA* key_pair = NULL;

		FILE* pub_file = fopen(argv[1], "r");
		key_pair = PEM_read_RSAPublicKey(pub_file, NULL, NULL, NULL);

		int key_size = RSA_size(key_pair);
		FILE* plain_file = fopen(argv[2], "rb");
		fseek(plain_file, 0x00, SEEK_END);
		unsigned long file_size = ftell(plain_file);

		unsigned int no_blocks_ciphertext = file_size / key_size;
		if ((file_size % key_size) != 0)
		{
			no_blocks_ciphertext += 1;
		}

		unsigned char* input = (unsigned char*)malloc(key_size);
		unsigned char* output = (unsigned char*)malloc(key_size);

		FILE* cipher_file = fopen(argv[3], "wb+");

		fseek(plain_file, 0x00, SEEK_SET);
		for (unsigned int i = 0; i < (no_blocks_ciphertext - 1); i++)
		{
			unsigned int read_bytes = fread(input, sizeof(unsigned char), key_size, plain_file);
			if (read_bytes != key_size)
			{
				printf("Error for plaintext file reading.\n");
				return 1;
			}
			int enc_size = RSA_public_encrypt(key_size, input, output, key_pair, RSA_NO_PADDING);
			if (enc_size != key_size)
			{
				printf("Encryption error.\n");
				return 2;
			}
			unsigned int write_bytes = fwrite(output, sizeof(unsigned char), enc_size, cipher_file);
			if (write_bytes != enc_size)
			{
				printf("Error for ciphertext to be written into the cipher file.\n");
				return 3;
			}
		}

		unsigned int read_bytes = fread(input, sizeof(unsigned char), key_size, plain_file);
		int enc_size = RSA_public_encrypt(read_bytes, input, output, key_pair, RSA_PKCS1_PADDING);
		if (enc_size != key_size)
		{
			printf("Encryption error.\n");
			return 2;
		}
		unsigned int write_bytes = fwrite(output, sizeof(unsigned char), enc_size, cipher_file);
		if (write_bytes != enc_size)
		{
			printf("Error for ciphertext to be written into the cipher file.\n");
			return 3;
		}

		printf("\nSuccessful RSA encryption with RSA public key.\n\n");

		RSA_free(key_pair);
		free(input);
		free(output);

		fclose(plain_file);
		fclose(cipher_file);
		fclose(pub_file);
	}
	else
	{
		printf("Incorrect argument count: app.exe RSAPublicKey.pem plain.txt cipher.file\n");
	}

	return 0;
}