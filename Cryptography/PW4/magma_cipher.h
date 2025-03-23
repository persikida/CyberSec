// magma_cipher.h
#ifndef MAGMA_CIPHER_H
#define MAGMA_CIPHER_H

#include <cstdint>
#include <vector>
#include <string>

uint32_t G(uint32_t a, uint32_t k);
std::vector<uint32_t> generateRoundKeys(const std::vector<uint8_t>& key);
std::vector<uint8_t> processBlock(const std::vector<uint8_t>& block, const std::vector<uint32_t>& round_keys, bool decrypt = false);
void processFile(const std::string& input_file, const std::string& output_file, const std::vector<uint8_t>& key, bool decrypt);
std::vector<uint8_t> applyPKCS7Padding(const std::vector<uint8_t>& data, size_t block_size);
std::vector<uint8_t> removePKCS7Padding(const std::vector<uint8_t>& data);

#endif // MAGMA_CIPHER_H
