// OpenSSL Exam Cheatsheet in C++
// Includes: SHA256, AES-CBC/ECB, RSA keygen, sign/verify, encryption/decryption
// Compile with: g++ cheatsheet.cpp -o cheatsheet -lcrypto -lssl
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
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

// --- Utility Functions ---
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

// --- SHA256 Hash ---
vector<unsigned char> sha256(const vector<unsigned char> &data)
{
    vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

// --- AES-256-CBC Encrypt ---
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

// --- AES-256-ECB Decrypt ---
vector<unsigned char> aesDecryptECB(const vector<unsigned char> &ciphertext, const vector<unsigned char> &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plaintext(ciphertext.size());
    int len, totalLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key.data(), NULL);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    totalLen += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    totalLen += len;

    plaintext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// --- RSA Key Generation ---
void generateRSAKey(const string &privFilename, const string &pubFilename)
{
    RSA *key_pair = NULL;

    // generate a RSA key pair
    key_pair = RSA_generate_key(1024, 17, NULL, NULL);

    FILE *priv_file = fopen(privFilename.c_str(), "w+");
    // save RSA private key into a PEM format file
    int result = PEM_write_RSAPrivateKey(priv_file, key_pair, NULL, NULL, 0, NULL, NULL);
    if (result != 1)
    {
        printf("Error during write the RSA private key into the file.\n");
    }

    FILE *pub_file = fopen(pubFilename.c_str(), "w+");
    // save RSA public key into a PEM format file
    result = PEM_write_RSAPublicKey(pub_file, key_pair);
    if (result != 1)
    {
        printf("Error during write the RSA public key into the file.\n");
    }

    printf("RSA key pair has been successfully generated.\n");

    RSA_free(key_pair); // deallocation of RSA structure done by openssl

    fclose(priv_file);
    fclose(pub_file);
}

vector<unsigned char> rsaSignLowLevel(const vector<unsigned char> &msg, const string &privKeyFile)
{
    // 1. Load the RSA Private Key from file
    FILE *fp = fopen(privKeyFile.c_str(), "rb");
    if (!fp)
        return {};

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa)
        return {};

    vector<unsigned char> digest = sha256(msg);

    // 3. Prepare the output buffer (128 bytes for RSA-1024)
    vector<unsigned char> sig(RSA_size(rsa));

    // 4. Perform RAW RSA Private Encryption (Hash + Encrypt)
    // This replaces RSA_sign to avoid the extra DigestInfo metadata
    int result = RSA_private_encrypt(
        (int)digest.size(), // Input: 32 bytes for SHA-256
        digest.data(),      // Input: The raw hash
        sig.data(),         // Output: The encrypted signature
        rsa,
        RSA_PKCS1_PADDING // Required padding type
    );

    if (result == -1)
    {
        RSA_free(rsa);
        return {}; // Handle encryption error
    }

    // 5. Cleanup and return
    sig.resize(result);
    RSA_free(rsa);
    return sig;
}

// --- RSA Sign (SHA256) ---
vector<unsigned char> rsaSign(const vector<unsigned char> &msg, const string &privKeyFile)
{
    FILE *fp = fopen(privKeyFile.c_str(), "rb");
    if (!fp)
        return {};

    // Load PKCS#1 Private Key
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa)
        return {};

    EVP_PKEY *pKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pKey, rsa); // pKey now owns the rsa pointer

    EVP_PKEY_CTX *pSignCtx = EVP_PKEY_CTX_new(pKey, NULL);
    EVP_PKEY_sign_init(pSignCtx);
    EVP_PKEY_CTX_set_rsa_padding(pSignCtx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_signature_md(pSignCtx, EVP_sha256());

    vector<unsigned char> digest = sha256(msg);
    size_t sigLen = 0;
    EVP_PKEY_sign(pSignCtx, NULL, &sigLen, digest.data(), digest.size());

    vector<unsigned char> sig(sigLen);
    EVP_PKEY_sign(pSignCtx, sig.data(), &sigLen, digest.data(), digest.size());

    EVP_PKEY_CTX_free(pSignCtx);
    EVP_PKEY_free(pKey); // Also frees rsa
    return sig;
}

// --- RSA Verify (SHA256) ---
bool rsaVerify(const vector<unsigned char> &msg, const vector<unsigned char> &sig, const string &pubKeyFile)
{
    // 1. Load Public Key
    FILE *fp = fopen(pubKeyFile.c_str(), "rb");
    if (!fp)
        return false;
    EVP_PKEY *pKey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pKey)
        return false;

    // 2. Setup Context
    EVP_PKEY_CTX *pCheckCtx = EVP_PKEY_CTX_new(pKey, NULL);
    EVP_PKEY_verify_init(pCheckCtx);

    // 3. Set Parameters (Ensure these match the Signing side!)
    EVP_PKEY_CTX_set_rsa_padding(pCheckCtx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_signature_md(pCheckCtx, EVP_sha256());

    // 4. Hash the message
    vector<unsigned char> digest = sha256(msg);

    // 5. Verify
    // EVP_PKEY_verify returns 1 for success, 0 for failure, < 0 for error
    int result = EVP_PKEY_verify(pCheckCtx, sig.data(), sig.size(), digest.data(), digest.size());

    // 6. Cleanup
    EVP_PKEY_CTX_free(pCheckCtx);
    EVP_PKEY_free(pKey);

    return (result == 1);
}

// --- RSA Public Encrypt ---
vector<unsigned char> rsaEncrypt(const vector<unsigned char> &data, const string &pubKeyFile)
{
    FILE *fp = fopen(pubKeyFile.c_str(), "rb");
    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);

    vector<unsigned char> encrypted(RSA_size(rsa));
    // RSA_PKCS1_PADDING is the standard for exams
    int result = RSA_public_encrypt(data.size(), data.data(), encrypted.data(), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        RSA_free(rsa);
        throw runtime_error("RSA Encryption failed");
    }

    RSA_free(rsa);
    return encrypted;
}

vector<unsigned char> aesEncryptECB(const vector<unsigned char> &plaintext, const vector<unsigned char> &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // Ciphertext size can be up to one block larger than plaintext due to padding
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, totalLen = 0;

    // Initialize Encryption using ECB mode (Note: IV is NULL)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key.data(), NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize ECB encryption");
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to update ECB encryption");
    }
    totalLen += len;

    // Finalize encryption (handles padding)
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

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    // EVP_CIPHER_CTX_set_padding(ctx, 0); padding disabled
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

// --- RSA Private Decrypt ---
vector<unsigned char> rsaDecrypt(const vector<unsigned char> &encryptedData, const string &privKeyFile)
{
    FILE *fp = fopen(privKeyFile.c_str(), "rb");
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    vector<unsigned char> decrypted(RSA_size(rsa));
    int result = RSA_private_decrypt(encryptedData.size(), encryptedData.data(), decrypted.data(), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        RSA_free(rsa);
        throw runtime_error("RSA Decryption failed");
    }

    decrypted.resize(result);
    RSA_free(rsa);
    return decrypted;
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

std::string bytesToHex(const std::vector<unsigned char> &data)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : data)
    {
        ss << std::setw(2) << (int)b;
    }
    return ss.str();
}

// --- RSA Private Encrypt (legacy "sign-like") ---
// Takes arbitrary small data, produces RSA_size(key) bytes.
// Use only if your exercise expects RSA_public_decrypt later.
vector<unsigned char> rsaPrivateEncrypt(const vector<unsigned char> &data, const string &privKeyFile)
{
    FILE *fp = fopen(privKeyFile.c_str(), "rb");
    if (!fp)
        throw runtime_error("Cannot open private key file");

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa)
        throw runtime_error("Failed to read private key");

    vector<unsigned char> out(RSA_size(rsa));

    // PKCS#1 v1.5 padding
    int n = RSA_private_encrypt(
        (int)data.size(),
        data.data(),
        out.data(),
        rsa,
        RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (n == -1)
        throw runtime_error("RSA_private_encrypt failed");

    // n should be RSA_size(rsa), but we still resize to what OpenSSL returns
    out.resize(n);
    return out;
}

// --- RSA Public Decrypt (legacy "verify-like") ---
// Reverses rsaPrivateEncrypt(). Output length is variable (<= RSA_size).
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

// --- Main Example (adapt as needed) ---
int main()
{
    string name = "Angelica Example";
    writeFile("HELPER/name.txt", vector<unsigned char>(name.begin(), name.end()));

    // 1. Compute SHA256
    auto nameContent = readFile("HELPER/name.txt");
    auto hash = sha256(nameContent);
    cout << "SHA-256: ";
    printHex(hash);

    // 2. AES-CBC encrypt
    vector<unsigned char> iv = readFile("HELPER/iv.txt");
    vector<unsigned char> key = readFile("HELPER/aes.key");
    auto encrypted = aesEncryptCBC(nameContent, key, iv);
    writeFile("HELPER/enc_name.aes", encrypted);

    // 3. RSA Sign
    generateRSAKey("HELPER/private.pem", "HELPER/public.pem");
    auto signature = rsaSign(nameContent, "HELPER/private.pem");
    writeFile("HELPER/digital.sign", signature);

    return 0;
}