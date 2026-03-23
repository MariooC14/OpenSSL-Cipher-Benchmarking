/**
 * Benchmarking structure is as follows:
 * Algorithm > 128/256-bit key version > Mode (ECB/CBC/CTR)
 * Algorithm = [128_modes, 256_modes]
 * 128/256 modes = [ECB, CBC, CTR]
 */

#include <cstring>
#include <fstream>
#include <iostream>
#include "openssl-benchmark.h"
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

const EVP_CIPHER *AES_CIPHER_128_MODES[] = {
    EVP_aes_128_ecb(),
    EVP_aes_128_cbc(),
    EVP_aes_128_ctr(),
};

const EVP_CIPHER *AES_CIPHER_256_MODES[] = {
    EVP_aes_256_ecb(),
    EVP_aes_256_cbc(),
    EVP_aes_256_ctr(),
};

const EVP_CIPHER *ARIA_CIPHER_128_MODES[] = {
    EVP_aria_128_ecb(),
    EVP_aria_128_cbc(),
    EVP_aria_128_ctr(),
};

const EVP_CIPHER *ARIA_CIPHER_256_MODES[] = {
    EVP_aria_256_ecb(),
    EVP_aria_256_cbc(),
    EVP_aria_256_ctr(),
};

const EVP_CIPHER *CAMELLIA_CIPHER_128_MODES[] = {
    EVP_camellia_128_ecb(),
    EVP_camellia_128_cbc(),
    EVP_camellia_128_ctr(),
};

const EVP_CIPHER *CAMELLIA_CIPHER_256_MODES[] = {
    EVP_camellia_256_ecb(),
    EVP_camellia_256_cbc(),
    EVP_camellia_256_ctr(),
};

const EVP_CIPHER **AES_CIPHERS[] = {
    AES_CIPHER_128_MODES, AES_CIPHER_256_MODES
};

const EVP_CIPHER **ARIA_CIPHERS[] = {
    ARIA_CIPHER_128_MODES, ARIA_CIPHER_256_MODES
};

const EVP_CIPHER **CAMELLIA_CIPHERS[] = {
    CAMELLIA_CIPHER_128_MODES, CAMELLIA_CIPHER_256_MODES
};

const EVP_CIPHER ***CIPHERS[] = {
    AES_CIPHERS, ARIA_CIPHERS, CAMELLIA_CIPHERS
};

const std::string CIPHER_NAMES[] = {
    "AES", "ARIA", "CAMELLIA"
};

const std::string MODE_NAMES[] = {"ECB", "CBC", "CTR"};

// Arbitrary keys
const unsigned char key_256[] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
};
const unsigned char key_128[] = {
    0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
};

/* 128-bit Initialization vector */
const unsigned char iv[] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
};

int main() {
    std::ofstream csv_file("benchmark-results.csv");
    if (!csv_file.is_open()) {
        std::cerr << "Failed to open benchmark-results.csv for writing." << std::endl;
        return 1;
    }

    csv_file << "Cipher,Key Size,Mode,Operation,Input Size,Clock Ticks\n";

    const auto write_csv_rows = [&csv_file](
        const std::string &cipher_name,
        const int key_size,
        const std::string& mode,
        const Benchmark &benchmark
    ) {
        csv_file << cipher_name << ',' << key_size << ',' << mode << ",Encryption,100MB," << benchmark.encryption_time_100mb << '\n';
        csv_file << cipher_name << ',' << key_size << ',' << mode << ",Decryption,100MB," << benchmark.decryption_time_100mb << '\n';
        csv_file << cipher_name << ',' << key_size << ',' << mode << ",Encryption,1GB," << benchmark.encryption_time_1gb << '\n';
        csv_file << cipher_name << ',' << key_size << ',' << mode << ",Decryption,1GB," << benchmark.decryption_time_1gb << '\n';
    };

    // Iterate through config by: cipher > key length > mode. Benchmark function handles encryption/decryption of 100Mb/1GB data.
    for (int cipherIdx = 0; cipherIdx < 3; ++cipherIdx) {
        std::cout << "Benchmarking " << CIPHER_NAMES[cipherIdx] << " cipher modes..." << std::endl;
        const auto cipher = CIPHERS[cipherIdx];
        const auto cipher_128 = cipher[0];
        const auto cipher_256 = cipher[1];

        Benchmark benchmarks_128[3] = {};
        Benchmark benchmarks_256[3] = {};

        for (int mode_Idx = 0; mode_Idx < 3; ++mode_Idx) {
            benchmark_cipher(cipher_128[mode_Idx], key_128, iv, benchmarks_128[mode_Idx]);
            benchmark_cipher(cipher_256[mode_Idx], key_256, iv, benchmarks_256[mode_Idx]);

            write_csv_rows(CIPHER_NAMES[cipherIdx], 128, MODE_NAMES[mode_Idx], benchmarks_128[mode_Idx]);
            write_csv_rows(CIPHER_NAMES[cipherIdx], 256, MODE_NAMES[mode_Idx], benchmarks_256[mode_Idx]);
        }

        std::cout << "Results:" << std::endl;
        for (int mode_Idx = 0; mode_Idx < 3; ++mode_Idx) {
            std::cout << "Mode: " << EVP_CIPHER_name(cipher_128[mode_Idx]) << std::endl;
            std::cout << "Encryption time for 100MB: " << benchmarks_128[mode_Idx].encryption_time_100mb <<
                    " clock ticks" << std::endl;
            std::cout << "Decryption time for 100MB: " << benchmarks_128[mode_Idx].decryption_time_100mb <<
                    " clock ticks" << std::endl;
            std::cout << "Encryption time for 1GB: " << benchmarks_128[mode_Idx].encryption_time_1gb << " clock ticks"
                    << std::endl;
            std::cout << "Decryption time for 1GB: " << benchmarks_128[mode_Idx].decryption_time_1gb << " clock ticks"
                    << std::endl;

            std::cout << "Mode: " << EVP_CIPHER_name(cipher_256[mode_Idx]) << std::endl;
            std::cout << "Encryption time for 100MB: " << benchmarks_256[mode_Idx].encryption_time_100mb <<
                    " clock ticks" << std::endl;
            std::cout << "Decryption time for 100MB: " << benchmarks_256[mode_Idx].decryption_time_100mb <<
                    " clock ticks" << std::endl;
            std::cout << "Encryption time for 1GB: " << benchmarks_256[mode_Idx].encryption_time_1gb << " clock ticks"
                    << std::endl;
            std::cout << "Decryption time for 1GB: " << benchmarks_256[mode_Idx].decryption_time_1gb << " clock ticks"
                    << std::endl;
        }
    }

    csv_file.close();
    std::cout << "CSV results written to benchmark-results.csv" << std::endl;

    return 0;
}
