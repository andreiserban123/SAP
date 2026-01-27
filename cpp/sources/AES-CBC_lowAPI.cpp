#include <malloc.h>
#include <memory.h>
#include <openssl/aes.h>
#include <stdio.h>

int main() {
  unsigned char plaintext[] = {0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f,
                               0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
                               0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f,
                               0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
                               0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0xaf};
  unsigned char key_256[] = {0xff, 0xab, 0xff, 0xce, 0x1f, 0x0d, 0x88, 0xe9,
                             0xab, 0xff, 0xec, 0xff, 0xf1, 0xc1, 0x99, 0xd8,
                             0xf1, 0xa1, 0xf1, 0xc1, 0x11, 0x01, 0x81, 0xe1,
                             0x2b, 0x2f, 0x2c, 0x2f, 0xf1, 0xc1, 0x99, 0xd8};
  unsigned char IV[] = {0xab, 0xbb, 0xcb, 0xdb, 0xeb, 0xa1, 0xa2, 0xa3,
                        0xa2, 0xa1, 0xa0, 0xa0, 0xa0, 0x1b, 0x3b, 0x3b};
  unsigned char IV_backup[AES_BLOCK_SIZE];

  // AES key + prepare the key for usage
  AES_KEY aes_key_256;

  ////////////////////////////////////////////////
  // Encrypt plaintext (AES-CBC)
  ////////////////////////////////////////////////
  AES_set_encrypt_key(key_256, (const int)(sizeof(key_256) * 8), &aes_key_256);

  unsigned short int no_blocks_ciphertext = sizeof(plaintext) / AES_BLOCK_SIZE;
  if (sizeof(plaintext) % AES_BLOCK_SIZE != 0) {
    no_blocks_ciphertext += 1;
  }

  unsigned char *ciphertext =
      (unsigned char *)malloc(no_blocks_ciphertext * AES_BLOCK_SIZE);
  memset(ciphertext, 0x00,
         no_blocks_ciphertext *
             AES_BLOCK_SIZE); // set nul values over ciphertext buffer

  // ecnrypt all plaintext content in one shot operation
  // after execution of AES_cbc_encrypt, the IV will be updated
  memcpy(IV_backup, IV, AES_BLOCK_SIZE);
  AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_key_256, IV,
                  AES_ENCRYPT);

  printf("Encryption AES_CBC: ");
  for (unsigned int i = 0;
       i < (unsigned int)(no_blocks_ciphertext * AES_BLOCK_SIZE); i++) {
    printf("%02X", ciphertext[i]);
  }
  printf("\n\n");

  ////////////////////////////////////////////////
  // Decrypt ciphertext (AES-CBC)
  ////////////////////////////////////////////////
  unsigned char *restore = (unsigned char *)malloc(sizeof(plaintext));
  AES_set_decrypt_key(key_256, (const int)(sizeof(key_256) * 8), &aes_key_256);

  unsigned char *decrypted_buffer =
      (unsigned char *)malloc(no_blocks_ciphertext * AES_BLOCK_SIZE);

  // IV must be the same for both encryption and decryption operations
  AES_cbc_encrypt(ciphertext, decrypted_buffer,
                  (no_blocks_ciphertext * AES_BLOCK_SIZE), &aes_key_256,
                  IV_backup, AES_DECRYPT);
  printf("Decryption AES-CBC: ");
  for (unsigned int i = 0;
       i < (unsigned int)(no_blocks_ciphertext * AES_BLOCK_SIZE); i++) {
    printf("%02X", decrypted_buffer[i]);
  }
  printf("\n\n");

  // copy the relevant content from temp buffer into restore buffer
  memcpy(restore, decrypted_buffer, sizeof(plaintext));
  if (memcmp(plaintext, restore, sizeof(plaintext)) == 0) {
    printf("Restored content is the same one with the original content.");
  } else {
    printf("Wrong encryption and/or decryption operations.");
  }

  printf("\n\n");

  free(ciphertext);
  free(decrypted_buffer);
  free(restore);

  return 0;
}
