
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
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
vector<unsigned char> aesDecryptECB(const vector<unsigned char> &ciphertext, const vector<unsigned char> &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plaintext(ciphertext.size());
    int len, totalLen = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    totalLen += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    totalLen += len;

    plaintext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

vector<unsigned char> sha256(const vector<unsigned char> &data)
{
    vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

void writeFile(const string &filename, const vector<unsigned char> &data)
{
    ofstream file(filename, ios::binary);
    file.write((char *)data.data(), data.size());
}

vector<unsigned char> rsaEncrypt(const vector<unsigned char> &data, const string &pubKeyFile)
{
    FILE *fp = fopen(pubKeyFile.c_str(), "rb");
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    vector<unsigned char> encrypted(RSA_size(rsa));
    // RSA_PKCS1_PADDING is the standard for exams
    int result = RSA_private_encrypt(data.size(), data.data(), encrypted.data(), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        RSA_free(rsa);
        throw runtime_error("RSA Encryption failed");
    }

    RSA_free(rsa);
    return encrypted;
}
int main()
{
    vector<unsigned char> key{
        0xff, 0xff, 0xff, 0xff,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x10, 0x11, 0x12};

    auto chip1 = readFile("privateKey_1.enc");
    auto chip2 = readFile("privateKey_2.enc");
    auto chip3 = readFile("privateKey_3.enc");

    // decrypt
    auto priv1 = aesDecryptECB(chip1, key);
    auto priv2 = aesDecryptECB(chip2, key);
    auto priv3 = aesDecryptECB(chip3, key);

    writeFile("priv_key1.key", priv1);
    writeFile("priv_key2.key", priv2);
    writeFile("priv_key3.key", priv3);

    auto bytes = readFile("in.txt");

    auto digest = sha256(bytes);

    auto sign1 = rsaEncrypt(digest, "priv_key1.key");
    auto sign2 = rsaEncrypt(digest, "priv_key2.key");
    auto sign3 = rsaEncrypt(digest, "priv_key3.key");

    auto esig = readFile("eSign.sig");
    cout << esig.size();
    if (esig == sign1)
    {
        cout << "first";
    }
    if (esig == sign2)
    {
        cout << "second";
    }
    if (esig == sign3)
    {
        cout << "third";
    }
    return 0;
}
