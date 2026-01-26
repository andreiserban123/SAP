#include <stdio.h>
#include <malloc.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

int main()
{
	unsigned char SHA_1[] = {
		0x01, 0xff, 0xfe, 0xcd, 0x11,
		0x02, 0xaf, 0xff, 0xbd, 0x12,
		0x03, 0xbf, 0xf0, 0xad, 0x13,
		0x04, 0xbf, 0xf1, 0x9d, 0x14,
	};
	unsigned char* signature = (unsigned char*)malloc(164); // 164 bytes allocated to store the signature after ECDSA generation
	unsigned int sig_len = 0;
	// Generate EC key pair
	EC_KEY* pECKeyPair = NULL;
	pECKeyPair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // initialize the pointer to EC_KEY with a certain EC

	EC_KEY_generate_key(pECKeyPair); // function to generate the EC key pair

	// Sign message to get ECDSA
	ECDSA_sign(0, SHA_1, SHA_DIGEST_LENGTH, signature, &sig_len, pECKeyPair);

	printf("ECDSA -> ");
	for (unsigned int i = 0; i < sig_len; i++)
	{
		printf("%02x", signature[i]);
	}
	printf("\n\n");

	// Verify ECDSA
	ECDSA_SIG* pSig = NULL;

	pSig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&signature, sig_len);
	int result = ECDSA_do_verify(SHA_1, SHA_DIGEST_LENGTH, pSig, pECKeyPair);
	if (result == 1)
	{
		printf("Succesful verification!\n\n");
	}
	else {
		if (result == 0)
		{
			printf("The ECDSA signature is not valid!\n\n");
		}
		else
		{
			printf("An error has occured during ECDSA verification!\n\n");
		}
	}

	return 0;
}