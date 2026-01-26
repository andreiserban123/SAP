#include <openssl/sha.h>
#include <stdio.h>

// Add into C/C++ -> General -> Additional Include Directories: path to the <openssl_bundle>/include
// Add *.lib file path into Linker-Input-Additional Dependencies
// Put *.dll file into the same path with *.exe file

int main()
{
	// message to be digested
	unsigned char message[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
							   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
							   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


	// get the final result of MD context structure
	unsigned char message_digest[SHA_DIGEST_LENGTH];
	SHA1(message, sizeof(message), message_digest); // SHA-1 computed in one single step for short enough input

	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02X ", message_digest[i]); // print out each byte as hex-pair letters over the screen
	printf("\n\n");


	return 0;
}