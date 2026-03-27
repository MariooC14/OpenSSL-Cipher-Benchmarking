#include <fstream>
#include <iostream>
#include <openssl/evp.h>

#include "openssl-benchmark.h"

const EVP_CIPHER *TRIPLE_DES_CIPHERS[] = {
    EVP_des_ede3_ecb(),
    EVP_des_ede3_cbc(),
};

const std::string MODE_NAMES[] = {"ECB", "CBC"};

// 3DES uses a 24-byte key (192-bit nominal key size).
const unsigned char key_3des[] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33
};

// DES block size is 8 bytes, so IV is 8 bytes for CBC.
const unsigned char iv_3des[] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
};

constexpr int PLAINTEXT_SIZE_100MB = 100 * 1024 * 1024;
constexpr int PLAINTEXT_SIZE_1GB = 1024 * 1024 * 1024;

int main() {
    std::ofstream csv_file("benchmark-results-3des.csv");
    if (!csv_file.is_open()) {
        std::cerr << "Failed to open benchmark-results-3des.csv for writing." << std::endl;
        return 1;
    }

    csv_file << "Cipher,Key Size,Mode,Operation,Input Size,Clock Ticks\n";

    const auto write_csv_rows = [&csv_file](const std::string &mode, const Benchmark &benchmark) {
        csv_file << "3DES,192," << mode << ",Encryption,100MB," << benchmark.encryption_time_100mb << '\n';
        csv_file << "3DES,192," << mode << ",Decryption,100MB," << benchmark.decryption_time_100mb << '\n';
        csv_file << "3DES,192," << mode << ",Encryption,1GB," << benchmark.encryption_time_1gb << '\n';
        csv_file << "3DES,192," << mode << ",Decryption,1GB," << benchmark.decryption_time_1gb << '\n';
    };

    std::cout << "Generating input data..." << std::endl;
    auto *plaintext_100mb = new unsigned char[PLAINTEXT_SIZE_100MB];
    auto *plaintext_1gb = new unsigned char[PLAINTEXT_SIZE_1GB];

    auto *ciphertext_100mb = new unsigned char[PLAINTEXT_SIZE_100MB + EVP_MAX_BLOCK_LENGTH];
    auto *ciphertext_1gb = new unsigned char[PLAINTEXT_SIZE_1GB + EVP_MAX_BLOCK_LENGTH];

    generate_plaintext_random(plaintext_100mb, PLAINTEXT_SIZE_100MB);
    generate_plaintext_random(plaintext_1gb, PLAINTEXT_SIZE_1GB);

    std::cout << "Benchmarking 3DES cipher modes..." << std::endl;
    Benchmark benchmarks[2] = {};

    for (int mode_idx = 0; mode_idx < 2; ++mode_idx) {
        benchmark_cipher(TRIPLE_DES_CIPHERS[mode_idx], key_3des, iv_3des, plaintext_100mb, plaintext_1gb,
                            PLAINTEXT_SIZE_100MB, PLAINTEXT_SIZE_1GB,
                            ciphertext_100mb, ciphertext_1gb,
                            benchmarks[mode_idx]);
        write_csv_rows(MODE_NAMES[mode_idx], benchmarks[mode_idx]);
    }

    std::cout << "Results:" << std::endl;
    for (int mode_idx = 0; mode_idx < 2; ++mode_idx) {
        std::cout << "Mode: " << EVP_CIPHER_name(TRIPLE_DES_CIPHERS[mode_idx]) << std::endl;
        std::cout << "Encryption time for 100MB: " << benchmarks[mode_idx].encryption_time_100mb << " clock ticks"
                  << std::endl;
        std::cout << "Decryption time for 100MB: " << benchmarks[mode_idx].decryption_time_100mb << " clock ticks"
                  << std::endl;
        std::cout << "Encryption time for 1GB: " << benchmarks[mode_idx].encryption_time_1gb << " clock ticks"
                  << std::endl;
        std::cout << "Decryption time for 1GB: " << benchmarks[mode_idx].decryption_time_1gb << " clock ticks"
                  << std::endl;
    }

    csv_file.close();
    std::cout << "CSV results written to benchmark-results-3des.csv" << std::endl;

    delete [] plaintext_100mb;
    delete [] plaintext_1gb;
    delete [] ciphertext_100mb;
    delete [] ciphertext_1gb;

    return 0;
}

