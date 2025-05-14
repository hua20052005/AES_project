#include "aes_modes.h"
#include <openssl/aes.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <random>

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}

static std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

void encrypt_file(const std::string& plaintext_file,
                  const std::string& key_file,
                  const std::string& iv_file,
                  const std::string& mode,
                  const std::string& cipher_file) {
    std::ifstream pf(plaintext_file);
    std::ifstream kf(key_file);
    std::ifstream ivf(iv_file);
    if (!pf || !kf || (mode != "ECB" && !ivf)) {
        std::cerr << "Error opening input files\n";
        exit(1);
    }

    std::string phex, khex, ivhex;
    std::getline(pf, phex);
    std::getline(kf, khex);
    if (mode != "ECB") std::getline(ivf, ivhex);

    auto plain = hex_to_bytes(phex);
    auto key = hex_to_bytes(khex);
    auto iv = hex_to_bytes(ivhex);

    AES_KEY aes_key_enc, aes_key_dec;
    if (AES_set_encrypt_key(key.data(), 128, &aes_key_enc) < 0) {
        std::cerr << "AES_set_encrypt_key failed\n";
        exit(1);
    }
    if (AES_set_decrypt_key(key.data(), 128, &aes_key_dec) < 0) {
        std::cerr << "AES_set_decrypt_key failed\n";
        exit(1);
    }

    std::vector<unsigned char> out(plain.size()), dec(plain.size());
    std::vector<unsigned char> iv_enc = iv, iv_dec = iv;

    if (mode == "ECB") {
        for (size_t i = 0; i < plain.size(); i += AES_BLOCK_SIZE) {
            AES_encrypt(plain.data() + i, out.data() + i, &aes_key_enc);
            AES_decrypt(out.data() + i, dec.data() + i, &aes_key_dec);
        }
    } else if (mode == "CBC") {
        AES_cbc_encrypt(plain.data(), out.data(), plain.size(), &aes_key_enc, iv_enc.data(), AES_ENCRYPT);
        AES_cbc_encrypt(out.data(), dec.data(), out.size(), &aes_key_dec, iv_dec.data(), AES_DECRYPT);
    } else if (mode == "CFB") {
        int num_enc = 0, num_dec = 0;
        AES_cfb8_encrypt(plain.data(), out.data(), plain.size(), &aes_key_enc, iv_enc.data(), &num_enc, AES_ENCRYPT);
        AES_cfb8_encrypt(out.data(), dec.data(), out.size(), &aes_key_dec, iv_dec.data(), &num_dec, AES_DECRYPT);
    } else if (mode == "OFB") {
        int num_enc = 0, num_dec = 0;
        AES_ofb128_encrypt(plain.data(), out.data(), plain.size(), &aes_key_enc, iv_enc.data(), &num_enc);
        AES_ofb128_encrypt(out.data(), dec.data(), out.size(), &aes_key_enc, iv_dec.data(), &num_dec);
    } else {
        std::cerr << "Unknown mode\n";
        exit(1);
    }

    std::ofstream cf(cipher_file);
    cf << bytes_to_hex(out);
    cf.close();
}

void benchmark_modes() {
    std::cout << "=== AES-128 加解密速率测试 ===" << std::endl;

    const size_t data_size = 10 * 1024 * 1024; // 10MB
    std::vector<unsigned char> plain(data_size);
    std::vector<unsigned char> cipher(data_size);
    std::vector<unsigned char> decrypted(data_size);
    std::vector<unsigned char> iv(AES_BLOCK_SIZE, 0x00);
    std::vector<unsigned char> iv_enc(AES_BLOCK_SIZE, 0x00);
    std::vector<unsigned char> iv_dec(AES_BLOCK_SIZE, 0x00);
    AES_KEY aes_key_enc, aes_key_dec;

    // 生成随机明文
    std::mt19937 rng(42);
    std::uniform_int_distribution<> dist(0, 255);
    for (auto& byte : plain) {
        byte = static_cast<unsigned char>(dist(rng));
    }

    // 固定的128-bit key
    unsigned char key[16] = {0};
    for (int i = 0; i < 16; ++i) {
        key[i] = i;
    }

    AES_set_encrypt_key(key, 128, &aes_key_enc);
    AES_set_decrypt_key(key, 128, &aes_key_dec);

    // ========================
    // 测 ECB
    // ========================
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < data_size; i += AES_BLOCK_SIZE) {
        AES_encrypt(plain.data() + i, cipher.data() + i, &aes_key_enc);
    }
    auto end = std::chrono::high_resolution_clock::now();
    double ecb_enc_time = std::chrono::duration<double>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < data_size; i += AES_BLOCK_SIZE) {
        AES_decrypt(cipher.data() + i, decrypted.data() + i, &aes_key_dec);
    }
    end = std::chrono::high_resolution_clock::now();
    double ecb_dec_time = std::chrono::duration<double>(end - start).count();

    std::cout << "ECB 加密速率: " << (data_size / 1024.0 / 1024.0) / ecb_enc_time << " MB/s\n";
    std::cout << "ECB 解密速率: " << (data_size / 1024.0 / 1024.0) / ecb_dec_time << " MB/s\n";

    // ========================
    // 测 CBC
    // ========================
    iv_enc = iv;
    start = std::chrono::high_resolution_clock::now();
    AES_cbc_encrypt(plain.data(), cipher.data(), data_size, &aes_key_enc, iv_enc.data(), AES_ENCRYPT);
    end = std::chrono::high_resolution_clock::now();
    double cbc_enc_time = std::chrono::duration<double>(end - start).count();

    iv_dec = iv;
    start = std::chrono::high_resolution_clock::now();
    AES_cbc_encrypt(cipher.data(), decrypted.data(), data_size, &aes_key_dec, iv_dec.data(), AES_DECRYPT);
    end = std::chrono::high_resolution_clock::now();
    double cbc_dec_time = std::chrono::duration<double>(end - start).count();

    std::cout << "CBC 加密速率: " << (data_size / 1024.0 / 1024.0) / cbc_enc_time << " MB/s\n";
    std::cout << "CBC 解密速率: " << (data_size / 1024.0 / 1024.0) / cbc_dec_time << " MB/s\n";

    // ========================
    // 测 CFB
    // ========================
    int num_cfb_enc = 0;
    iv_enc = iv;
    start = std::chrono::high_resolution_clock::now();
    AES_cfb8_encrypt(plain.data(), cipher.data(), data_size, &aes_key_enc, iv_enc.data(), &num_cfb_enc, AES_ENCRYPT);
    end = std::chrono::high_resolution_clock::now();
    double cfb_enc_time = std::chrono::duration<double>(end - start).count();

    int num_cfb_dec = 0;
    iv_dec = iv;
    start = std::chrono::high_resolution_clock::now();
    AES_cfb8_encrypt(cipher.data(), decrypted.data(), data_size, &aes_key_dec, iv_dec.data(), &num_cfb_dec, AES_DECRYPT);
    end = std::chrono::high_resolution_clock::now();
    double cfb_dec_time = std::chrono::duration<double>(end - start).count();

    std::cout << "CFB 加密速率: " << (data_size / 1024.0 / 1024.0) / cfb_enc_time << " MB/s\n";
    std::cout << "CFB 解密速率: " << (data_size / 1024.0 / 1024.0) / cfb_dec_time << " MB/s\n";

    // ========================
    // 测 OFB
    // ========================
    int num_ofb_enc = 0;
    iv_enc = iv;
    start = std::chrono::high_resolution_clock::now();
    AES_ofb128_encrypt(plain.data(), cipher.data(), data_size, &aes_key_enc, iv_enc.data(), &num_ofb_enc);
    end = std::chrono::high_resolution_clock::now();
    double ofb_enc_time = std::chrono::duration<double>(end - start).count();

    int num_ofb_dec = 0;
    iv_dec = iv;
    start = std::chrono::high_resolution_clock::now();
    AES_ofb128_encrypt(cipher.data(), decrypted.data(), data_size, &aes_key_enc, iv_dec.data(), &num_ofb_dec);
    end = std::chrono::high_resolution_clock::now();
    double ofb_dec_time = std::chrono::duration<double>(end - start).count();

    std::cout << "OFB 加密速率: " << (data_size / 1024.0 / 1024.0) / ofb_enc_time << " MB/s\n";
    std::cout << "OFB 解密速率: " << (data_size / 1024.0 / 1024.0) / ofb_dec_time << " MB/s\n";
}
