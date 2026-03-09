/* Create a header file for each source code file using the same name, but with a "*.h" extension. */
/* Keep it in the same folder as the source code file, and include it via #include "file.h" */

#ifndef OPENSSL_BENCHMARK /* This symbolic name is unique and should match the file name. */
#define OPENSSL_BENCHMARK /* This expression makes sure that this header file is only included once. */
#include <openssl/types.h>
#include <time.h>

struct Benchmark {
    clock_t encryption_time_100mb;
    clock_t encryption_time_1gb;
    clock_t decryption_time_100mb;
    clock_t decryption_time_1gb;
};

void handleErrors();
void generate_plaintext(unsigned char *plaintext, int size);
int encrypt(const unsigned char *plaintext,
            int plaintext_len,
            const EVP_CIPHER *cipher,
            const unsigned char *key,
            const unsigned char *iv,
            unsigned char *ciphertext);

int decrypt(const unsigned char *ciphertext,
        int ciphertext_len,
        const EVP_CIPHER *cipher,
        const unsigned char *key,
        const unsigned char *iv,
        unsigned char *plaintext);

void benchmark_cipher(const EVP_CIPHER* cipher, const unsigned char key[], const unsigned char iv[], Benchmark& benchmark);

#endif