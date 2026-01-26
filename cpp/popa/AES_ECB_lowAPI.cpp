#include <openssl/aes.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>

int main()
{
	unsigned char plaintext[] = { 0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f,
								  0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
								  0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f,
								  0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
								  0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0xaf };
	unsigned char key_128[] = {0xff, 0xab, 0xff, 0xce, 0x1f, 0x0d, 0x88, 0xe9, 
							   0xab, 0xff, 0xec, 0xff, 0xf1, 0xc1, 0x99, 0xd8};
	// AES key + prepare the key for usage
	AES_KEY aes_key_128;

	////////////////////////////////////////////////
	// Encrypt plaintext 
	////////////////////////////////////////////////
	AES_set_encrypt_key(key_128, (const int)(sizeof(key_128) * 8), &aes_key_128);

	// encrypt the plaintext at AES block level
	unsigned short int no_block_ciphertext = sizeof(plaintext) / AES_BLOCK_SIZE;
	if (sizeof(plaintext) % AES_BLOCK_SIZE != 0)
	{
		no_block_ciphertext += 1; // there is a last partial block in plaintext
	}

	unsigned char *ciphertext = (unsigned char *)malloc(no_block_ciphertext * AES_BLOCK_SIZE);

	for (unsigned short int i = 0; i < (no_block_ciphertext - 1); i++)
	{
		AES_encrypt(plaintext + (i * AES_BLOCK_SIZE), 
					ciphertext + (i * AES_BLOCK_SIZE), 
					&aes_key_128);
	}
	if (sizeof(plaintext) % AES_BLOCK_SIZE != 0)
	{
		// there is a last partial block in the plaintext
		unsigned char last_partial_block[AES_BLOCK_SIZE]; // temp buffer to store the last partial block in plaintext
		unsigned char no_bytes = sizeof(plaintext) % AES_BLOCK_SIZE; // no of bytes of last partial block in plaintext
		memset(last_partial_block, 0x00, AES_BLOCK_SIZE); // set all bytes to zero
		memcpy(last_partial_block, plaintext + (sizeof(plaintext) - no_bytes), no_bytes); // copy the relevant content from plaintext to temp buffer

		AES_encrypt(last_partial_block,
			ciphertext + ((no_block_ciphertext - 1) * AES_BLOCK_SIZE),
			&aes_key_128); // last_partial_block has last bytes on nul values
	}
	else {
		// the last block in plaintext is full filled in by content to be encrypted
		AES_encrypt(plaintext + (sizeof(plaintext) - AES_BLOCK_SIZE),
			ciphertext + (sizeof(plaintext) - AES_BLOCK_SIZE),
			&aes_key_128);
	}
	
	for (unsigned int i = 0; i < (unsigned int)(no_block_ciphertext * AES_BLOCK_SIZE); i++)
	{
		printf("%02X", ciphertext[i]);
	}

	printf("\n\n");

	////////////////////////////////////////////////
	// Decrypt ciphertext 
	////////////////////////////////////////////////
	AES_set_decrypt_key(key_128, (const int)(sizeof(key_128) * 8), &aes_key_128);
	unsigned char* restore = (unsigned char*)malloc(sizeof(plaintext));
	memset(restore, 0x00, sizeof(plaintext));

	for (unsigned short int i = 0; i < (unsigned short int)(no_block_ciphertext - 1); i++)
	{
		AES_decrypt(ciphertext + (i * AES_BLOCK_SIZE),
			restore + (i * AES_BLOCK_SIZE),
			&aes_key_128);
	}
	if (sizeof(plaintext) % AES_BLOCK_SIZE != 0)
	{
		// there is a last partial block in the plaintext/restore buffer
		unsigned char last_partial_block[AES_BLOCK_SIZE]; // temp buffer to store the last block decrypted from ciphertext
		unsigned char no_bytes = sizeof(plaintext) % AES_BLOCK_SIZE; // no of bytes of last partial block in plaintext
		memset(last_partial_block, 0x00, AES_BLOCK_SIZE);

		AES_decrypt(ciphertext + ((no_block_ciphertext * AES_BLOCK_SIZE) - AES_BLOCK_SIZE),
			last_partial_block,
			&aes_key_128);

		memcpy(restore + (sizeof(plaintext) - no_bytes), last_partial_block, no_bytes);
	}
	else
	{
		// the last block in plaintext si aligned to AES_BLOCK_SIZE (16 bytes)
		AES_decrypt(ciphertext + ((no_block_ciphertext * AES_BLOCK_SIZE) -  AES_BLOCK_SIZE),
			restore + ((no_block_ciphertext * AES_BLOCK_SIZE) - AES_BLOCK_SIZE),
			&aes_key_128);
	}

	if (memcmp(plaintext, restore, sizeof(plaintext)) == 0)
	{
		printf("Restore buffer content matches the plaintext.");
	}
	else
	{
		printf("Wrong AES-ECB encryption and/or decryption operations.");
	}

	printf("\n\n");

	free(ciphertext);
	free(restore);
	return 0;
}