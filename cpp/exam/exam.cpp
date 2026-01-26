#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/applink.c>
#include <openssl/pem.h>

void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main()
{
    const char *fullName = "Andrei Serban";
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

    FILE *f_name = fopen("name.txt", "w");
    fprintf(f_name, "%s", fullName);
    fclose(f_name);

    SHA256((const unsigned char *)fullName, strlen(fullName), sha256_hash);
    printf("SHA-256 hash: ");
    print_hex(sha256_hash, SHA256_DIGEST_LENGTH);

    unsigned char iv[AES_BLOCK_SIZE];
    FILE *f_iv = fopen("iv.txt", "r");
    for (int i = 0; i < 16; i++)
    {
        unsigned int temp;
        fscanf(f_iv, " 0x%x,", &temp);
        iv[i] = (unsigned char)temp;
    }
    fclose(f_iv);

    // Load Key (Binary format)
    unsigned char key[32];
    FILE *f_key = fopen("aes.key", "rb");
    fread(key, 1, 32, f_key);
    fclose(f_key);

    // 3. Conditional Padding and AES-256-CBC Encryption
    size_t len = strlen(fullName);
    unsigned short int no_blocks = len / AES_BLOCK_SIZE;
    if (len % AES_BLOCK_SIZE != 0)
    {
        no_blocks += 1; // Only add a block if not divisible
    }
    size_t padded_len = no_blocks * AES_BLOCK_SIZE;

    unsigned char *plaintext_padded = (unsigned char *)calloc(padded_len, 1);
    memcpy(plaintext_padded, fullName, len);
    unsigned char *ciphertext = (unsigned char *)malloc(padded_len);

    AES_KEY aes_key_256;
    AES_set_encrypt_key(key, 256, &aes_key_256); // Using 256-bit key

    // IV is updated after execution, so use a copy if needed later
    unsigned char iv_backup[16];
    memcpy(iv_backup, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(plaintext_padded, ciphertext, padded_len, &aes_key_256, iv, AES_ENCRYPT);

    FILE *f_enc = fopen("enc_name.aes", "wb");
    fwrite(ciphertext, 1, padded_len, f_enc);
    fclose(f_enc);

    // 4. Requirement 3: RSA-1024 Keygen and Digital Signature
    // Generate key pair

    printf("Application finished. All files generated.\n");

    RSA *key_pair = NULL;
    key_pair = RSA_generate_key(1024, 17, NULL, NULL);

    FILE *pub_file = fopen("RSAPublicKey.pem", "w+");
    int result = PEM_write_RSAPublicKey(pub_file, key_pair);
    if (result != 1)
    {
        printf("Error during write the RSA public key into the file.\n");
        return 1;
    }
    int key_size = RSA_size(key_pair); // RSA key size in number of bytes
    unsigned char *signature = (unsigned char *)malloc(key_size);
    memset(signature, 0x00, key_size);
    RSA_private_encrypt(SHA256_DIGEST_LENGTH, sha256_hash, signature, key_pair, RSA_PKCS1_PADDING);

    FILE *sign_file = fopen("digital.sign", "wb");

    fwrite(signature, 1, key_size, sign_file);

    fclose(sign_file);

    // Verification logic
    unsigned char *restore_hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    // RSA_public_decrypt returns the size of the recovered data
    int dec_sig_size = RSA_public_decrypt(RSA_size(key_pair), signature,
                                          restore_hash, key_pair, RSA_PKCS1_PADDING);

    if (memcmp(sha256_hash, restore_hash, SHA256_DIGEST_LENGTH) == 0)
    {
        printf("Signature is valid.\n");
    }
    else
    {
        printf("Signature is NOT valid.\n");
    }

    unsigned char *decrypted_text = (unsigned char *)malloc(padded_len);
    AES_KEY aes_decrypt_key;
    AES_set_decrypt_key(key, 256, &aes_decrypt_key);
    AES_cbc_encrypt(ciphertext, decrypted_text, padded_len, &aes_decrypt_key, iv_backup, AES_DECRYPT);

    if (memcmp(plaintext_padded, decrypted_text, padded_len) == 0)
    {
        printf("AES Decryption: SUCCESS\n");
    }
    else
    {
        printf("AES Decryption: FAILURE\n");
    }

    printf("Application finished. All files generated.\n");

    free(restore_hash);

    free(plaintext_padded);
    free(ciphertext);
    free(signature);
    RSA_free(key_pair);

    return 0;
}