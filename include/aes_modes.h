#ifndef AES_MODES_H
#define AES_MODES_H

#include <string>

// Encrypt file based on mode: ECB, CBC, CFB, OFB
void encrypt_file(const std::string& plaintext_file,
                  const std::string& key_file,
                  const std::string& iv_file,
                  const std::string& mode,
                  const std::string& cipher_file);

// Benchmark all modes
void benchmark_modes();

#endif // AES_MODES_H