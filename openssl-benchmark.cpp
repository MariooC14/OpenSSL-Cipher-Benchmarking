#include "openssl-benchmark.h"

#include <cstring>
#include <string>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <iostream>

/**
 * Benchmark the encryption and decryption of a given cipher with specified key and IV, storing the results in the provided benchmark struct.
 * @param cipher
 * @param key The cipher key
 * @param iv The initialization vector
 * @param plaintext_100mb The 100MB plaintext to encrypt
 * @param plaintext_1gb The 1GB plaintext to encrypt
 * @param plaintext_100mb_len The length of the 100MB plaintext
 * @param plaintext_1gb_len The length of the 1GB plaintext
 * @param ciphertext_100mb The buffer to store the resulting 100MB ciphertext
 * @param ciphertext_1gb The buffer to store the resulting 1GB ciphertext
 * @param benchmark The benchmark struct to store the results in
 */
void benchmark_cipher(const EVP_CIPHER *cipher, const unsigned char key[], const unsigned char iv[],
                      const unsigned char plaintext_100mb[], const unsigned char plaintext_1gb[],
                      const int plaintext_100mb_len, const int plaintext_1gb_len,
                      unsigned char ciphertext_100mb[], unsigned char ciphertext_1gb[],
                      Benchmark &benchmark) {
    auto start_100mb = clock();
    const size_t encrypted_100mb_len = encrypt(
        plaintext_100mb,
        plaintext_100mb_len,
        cipher,
        key,
        iv,
        ciphertext_100mb
    );
    benchmark.encryption_time_100mb = clock() - start_100mb;

    auto start_1gb = clock();
    const size_t ciphertext_1gb_len = encrypt(
        plaintext_1gb,
        plaintext_1gb_len,
        cipher,
        key,
        iv,
        ciphertext_1gb
    );
    benchmark.encryption_time_1gb = clock() - start_1gb;

    auto *decryptedText_100mb = new unsigned char[plaintext_100mb_len + EVP_MAX_BLOCK_LENGTH];
    auto *decryptedText_1gb = new unsigned char[plaintext_1gb_len];

    start_100mb = clock();
    const size_t decryptedText_100mb_len = decrypt(
        ciphertext_100mb,
        encrypted_100mb_len,
        cipher,
        key,
        iv,
        decryptedText_100mb
    );
    benchmark.decryption_time_100mb = clock() - start_100mb;

    decryptedText_100mb[decryptedText_100mb_len] = '\0';

    start_1gb = clock();
    const size_t decryptedText_1gb_len = decrypt(
        ciphertext_1gb,
        static_cast<int>(ciphertext_1gb_len),
        cipher,
        key,
        iv,
        decryptedText_1gb
    );
    benchmark.decryption_time_1gb = clock() - start_1gb;

    decryptedText_1gb[decryptedText_1gb_len] = '\0';

    delete[] decryptedText_100mb;
    delete[] decryptedText_1gb;
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * Encrypts the given plaintext using the specified cipher, key, and IV, and stores the resulting ciphertext in the provided buffer. Returns the length of the ciphertext.
 * Adapted from the assignment instructions
 */
int encrypt(const unsigned char *plaintext,
            const int plaintext_len,
            const EVP_CIPHER *cipher,
            const unsigned char *key,
            const unsigned char *iv,
            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialize the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256-bit AES (i.e. a 256-bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    int ciphertext_len = len;

    // Finalize encryption. Further ciphertext bytes may be written at this stage.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(const unsigned char *ciphertext,
            const int ciphertext_len,
            const EVP_CIPHER *cipher,
            const unsigned char *key,
            const unsigned char *iv,
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) // Create and initialize the context
        handleErrors();

    /*
     * Initialize the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256-bit AES (i.e. a 256-bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    int plaintext_len = len;

    // Finalize decryption. Further plaintext bytes may be written at this stage.
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
