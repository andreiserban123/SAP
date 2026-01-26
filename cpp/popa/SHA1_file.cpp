#include <openssl/sha.h>
#include <stdio.h>

// Add into C/C++ -> General -> Additional Include Directories: path to the <openssl_bundle>/include
// Add *.lib file path into Linker-Input-Additional Dependencies
// Put *.dll file into the same path with *.exe file

#define MESSAGE_BLOCK_LENGTH 11 // byte length of each message block to split the message

int main()
{
	// message to be digested
	unsigned char message[MESSAGE_BLOCK_LENGTH];
	FILE* file = NULL;

	file = fopen("message.bin", "rb");

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
	unsigned short int bytes_read = 0; // how many bytes have been read from the file
	bytes_read = (unsigned short int)fread(message, sizeof(unsigned char), MESSAGE_BLOCK_LENGTH, file);
	while (bytes_read > 0) // there is still something to pe passed to SHA1 update
	{
		result = SHA1_Update(&shaContext,
			(unsigned char*)message,
			bytes_read);
		if (!result)
		{
			printf("Error during SHA1_Update() for %d bytes\n", MESSAGE_BLOCK_LENGTH);
			return 2;
		}

		bytes_read = (unsigned short int)fread(message, sizeof(unsigned char), MESSAGE_BLOCK_LENGTH, file);
	}

	// get the final result of MD context structure
	unsigned char message_digest[SHA_DIGEST_LENGTH];
	result = SHA1_Final(message_digest, &shaContext); // final MD computation results are saved into output buffer (message_digest)
	if (!result)
	{
		printf("Error during SHA1_Final()\n");
		return 3;
	}

	// print out the console the SHA-1 MD
	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02X", message_digest[i]); // write each byte as hex-pair letters over the screen


	// save SHA-1 MD into a text file
	FILE* md_txt_file = fopen("SHA-1.txt", "w+");
	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
		fprintf(md_txt_file, "%02X", message_digest[i]); // save/write each byte as hex-pair letters into SHA-1.txt
	
	// save SHA-1 MD into a binary file
	FILE* md_bin_file = fopen("SHA-1.hash", "wb+");
	unsigned int bytes_written = fwrite(message_digest, sizeof(unsigned char), SHA_DIGEST_LENGTH, md_bin_file);
	if (bytes_written != SHA_DIGEST_LENGTH)
	{
		printf("Error during saving the MD into the binary file.\n");
	}
	
	printf("\n\n");

	fclose(file);
	fclose(md_txt_file);
	fclose(md_bin_file);

	return 0;
}