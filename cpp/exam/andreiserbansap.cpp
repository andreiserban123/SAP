#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/applink.c>

unsigned char *read_file(const char *filename, size_t *size)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buffer = (unsigned char *)malloc(*size);
    fread(buffer, 1, *size, f);
    fclose(f);
    return buffer;
}

int main()
{
    unsigned char aes_key_128[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[] = {0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12};

    size_t cipher_size = 0;
    unsigned char *ciphertext = read_file("encrypted.aes", &cipher_size);
    if (!ciphertext)
    {
        printf("Could not open encrypted.aes\n");
        return 1;
    }

    AES_KEY decrypt_key;
    AES_set_decrypt_key(aes_key_128, 128, &decrypt_key);

    unsigned char *restored_buffer = (unsigned char *)malloc(cipher_size);
    AES_cbc_encrypt(ciphertext, restored_buffer, cipher_size, &decrypt_key, iv, AES_DECRYPT);

    FILE *restored_file = fopen("restored.txt", "wb");
    if (restored_file == NULL)
    {
        printf("The restored.txt file could not be openned!");
        return 1;
    }

    fwrite(restored_buffer, 1, cipher_size, restored_file);
    fclose(restored_file);
    printf("1. Content decrypted to restored.txt\n");

    FILE *pub_key_file = fopen("public.pem", "r");

    if (pub_key_file == NULL)
    {
        printf("The public.pem file could not be openned!\n");
        return 1;
    }

    RSA *rsa_pub = PEM_read_RSAPublicKey(pub_key_file, NULL, NULL, NULL);
    fclose(pub_key_file);

    size_t sig_size = 0;
    unsigned char *signature = read_file("esign.sig", &sig_size);

    unsigned char *decrypted_digest = (unsigned char *)malloc(RSA_size(rsa_pub));
    int decrypted_len = RSA_public_decrypt(sig_size, signature, decrypted_digest, rsa_pub, RSA_PKCS1_PADDING);

    if (decrypted_len == -1)
    {
        printf("RSA decryption failed.\n");
    }
    else
    {
        FILE *sha_file = fopen("SHA-256.txt", "w");

        if (sha_file == NULL)
        {
            printf("The SHA-256.txt file could not be openned!\n");
            return 1;
        }

        for (int i = 0; i < decrypted_len; i++)
        {
            fprintf(sha_file, "%02x", decrypted_digest[i]);
        }
        fclose(sha_file);
        printf("2. RSA Signature decrypted to SHA-256.txt\n");
    }

    unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, restored_buffer, cipher_size);
    SHA256_Final(calculated_hash, &sha_ctx);

    int match = 0;
    if (decrypted_len >= SHA256_DIGEST_LENGTH)
    {
        if (memcmp(calculated_hash, decrypted_digest + (decrypted_len - SHA256_DIGEST_LENGTH), SHA256_DIGEST_LENGTH) == 0)
        {
            match = 1;
        }
    }
    if (match == 1)
    {
        printf("3. Validation Result: %s\n", "SIGNATURE VALID");
    }
    else
    {
        printf("3. Validation Result: %s\n", "SIGNATURE INVALID");
    }

    free(ciphertext);
    free(restored_buffer);
    free(signature);
    free(decrypted_digest);
    RSA_free(rsa_pub);

    return 0;
}