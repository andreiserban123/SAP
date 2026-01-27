#include <malloc.h>
#include <stdio.h>
#include <openssl/evp.h>

int main()
{
	unsigned char input[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf0
	};
	EVP_MD_CTX* pCtx = NULL;
	EVP_MD* pMD = NULL;

	pCtx = EVP_MD_CTX_new();
	pMD = (EVP_MD*)EVP_sha3_256();

	// initialization of MD and MD context
	EVP_DigestInit_ex(pCtx, pMD, NULL);

	// update internal structures (rounds)
	//EVP_DigestUpdate(pCtx, input, sizeof(input)); // OneShot case
	EVP_DigestUpdate(pCtx, input, 5);  // call #1 to update
	EVP_DigestUpdate(pCtx, (const unsigned char*)(input + 5), (unsigned int)(sizeof(input) - 5));  // call #2 to update

	// final operations
	int size = EVP_MD_size(pMD);
	unsigned char* digest = (unsigned char*)malloc(size);
	unsigned int digest_len = 0;
	EVP_DigestFinal(pCtx, digest, &digest_len);


	printf("SHA-3 256 (%d Bytes) -> ", digest_len);
	for (unsigned int i = 0; i < digest_len; i++)
	{
		printf("%02x", digest[i]);
	}
	printf("\n\n");

	EVP_MD_CTX_free(pCtx); // deallocate the context
	free(digest);
	return 0;
}