#include <openssl/sha.h>
#include <stdio.h>

// Add into C/C++ -> General -> Additional Include Directories: path to the <openssl_bundle>/include
// Add *.lib file path into Linker-Input-Additional Dependencies
// Put *.dll file into the same path with *.exe file

#define MESSAGE_BLOCK_LENGTH 11 // byte length of each message block to split the message

int main()
{
	// message to be digested
	unsigned char message[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
							   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
							   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	// define an openssl context structure variable
	SHA_CTX shaContext;

	// initialize the MD context structure
	int result = SHA1_Init(&shaContext); // call to openssl API
	if (!result)
	{
		printf("Error during SHA1_Init()\n");
		return 1;
	}

	// update the MD context structure
	unsigned short int remaining_length = sizeof(message); // length to be passed to SHA1 update
														   // in the next iterations
	while (remaining_length > 0) // there is still something to pe passed to SHA1 update
	{
		if (remaining_length > MESSAGE_BLOCK_LENGTH) // there is still enough content to pass as block to SHA1 update
		{
			result = SHA1_Update(&shaContext,
				(unsigned char*)(message + sizeof(message) - remaining_length),
				MESSAGE_BLOCK_LENGTH);
			if (!result)
			{
				printf("Error during SHA1_Update() for %d bytes\n", MESSAGE_BLOCK_LENGTH);
				return 2;
			}
			remaining_length -= MESSAGE_BLOCK_LENGTH;
		}
		else
		{ // remaining length is less predefined message block length
			result = SHA1_Update(&shaContext,
				(unsigned char*)(message + sizeof(message) - remaining_length),
				remaining_length);
			if (!result)
			{
				printf("Error during SHA1_Update() for %d bytes\n", remaining_length);
				return 2;
			}
			remaining_length -= remaining_length;
		}
	}

	// get the final result of MD context structure
	unsigned char message_digest[SHA_DIGEST_LENGTH];
	result = SHA1_Final(message_digest, &shaContext); // final MD computation results are saved into output buffer (message_digest)
	if (!result)
	{
		printf("Error during SHA1_Final()\n");
		return 3;
	}

	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02X ", message_digest[i]); // print out each byte as hex-pair letters over the screen
	printf("\n\n");


	return 0;
}