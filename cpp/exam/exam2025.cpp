#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/applink.c> // REQUIRED for Windows

using namespace std;

vector<unsigned char> readFile(const string &filename)
{
    ifstream file(filename, ios::binary);
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

void writeFile(const string &filename, const vector<unsigned char> &data)
{
    ofstream file(filename, ios::binary);
    file.write((char *)data.data(), data.size());
}

void printHex(const vector<unsigned char> &data)
{
    for (unsigned char byte : data)
        cout << hex << setw(2) << setfill('0') << (int)byte;
    cout << dec << endl;
}

vector<unsigned char> sha256(const vector<unsigned char> &data)
{
    vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

vector<unsigned char> aesEncryptCBC(const vector<unsigned char> &plaintext, const vector<unsigned char> &key, const vector<unsigned char> &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, totalLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    totalLen += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    totalLen += len;

    ciphertext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

vector<unsigned char> hexToBytes(const std::string &hex)
{
    if (hex.size() % 2 != 0)
        throw std::runtime_error("Hex string length must be even");

    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    char temp_hex[3] = {0};
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        temp_hex[0] = hex[i];
        temp_hex[1] = hex[i + 1];
        out.push_back(strtoul(temp_hex, NULL, 16));
    }
    return out;
}
vector<unsigned char> rsaSign(const vector<unsigned char> &msg, const string &privKeyFile)
{
    FILE *fp = fopen(privKeyFile.c_str(), "rb");
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    vector<unsigned char> sig(RSA_size(rsa));
    unsigned int sigLen;

    vector<unsigned char> digest = sha256(msg);
    RSA_sign(NID_sha256, digest.data(), digest.size(), sig.data(), &sigLen, rsa);

    sig.resize(sigLen);
    RSA_free(rsa);
    return sig;
}
vector<unsigned char> aesEncryptECB(const vector<unsigned char> &plaintext, const vector<unsigned char> &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, totalLen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key.data(), NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize ECB encryption");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to update ECB encryption");
    }
    totalLen += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to finalize ECB encryption");
    }
    totalLen += len;

    ciphertext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// EVP_CIPHER_CTX_set_padding(ctx, 0); padding disabled
vector<unsigned char> aesDecryptCBC(const vector<unsigned char> &ciphertext, const vector<unsigned char> &key, const vector<unsigned char> &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plaintext(ciphertext.size());
    int len, totalLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    totalLen += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed (Check key/IV or padding)");
    }
    totalLen += len;

    plaintext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
vector<unsigned char> rsaPublicDecrypt(const vector<unsigned char> &encryptedData, const string &pubKeyFile)
{
    FILE *fp = fopen(pubKeyFile.c_str(), "rb");
    if (!fp)
        throw runtime_error("Cannot open public key file");

    // For "-----BEGIN RSA PUBLIC KEY-----"
    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa)
        throw runtime_error("Failed to read public key");

    vector<unsigned char> out(RSA_size(rsa));

    int n = RSA_public_decrypt(
        (int)encryptedData.size(),
        encryptedData.data(),
        out.data(),
        rsa,
        RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (n == -1)
        throw runtime_error("RSA_public_decrypt failed");

    out.resize(n);
    return out;
}

int main()
{
    vector<unsigned char> aes_key_128{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x00, 0x00, 0x00, 0x00};
    vector<unsigned char> iv{0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12};
    auto cipherText = readFile("encrypted.aes");
    auto decrypted = aesDecryptCBC(cipherText, aes_key_128, iv);
    FILE *out = fopen("restore.txt", "w");
    for (int i = 0; i < decrypted.size(); i++)
    {
        fprintf(out, "%c", decrypted[i]);
    }
    auto esign = readFile("esign.sig");
    auto decryptedRsa = rsaPublicDecrypt(esign, "public.pem");

    FILE *f = fopen("SHA-256.txt", "w");
    for (int i = 0; i < decryptedRsa.size(); i++)
    {
        fprintf(f, "%02x", decryptedRsa[i]);
    }
    fclose(f);
    fclose(out);
    auto md = sha256(decrypted);

    vector<unsigned char> sigHash(
        decryptedRsa.end() - 32,
        decryptedRsa.end());

    if (md == sigHash)
    {
        cout << "Signature valid";
    }
    else
    {
        cout << "Signature invalid";
    }

    return 0;
}
