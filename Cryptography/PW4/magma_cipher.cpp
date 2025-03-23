// magma_cipher.cpp
#include "magma_cipher.h"
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <filesystem>

constexpr uint8_t SBOX[8][16] = {
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
    {6, 8, 2, 3, 9, 10, 5, 12, 1, 11, 7, 13, 0, 4, 15, 14},
    {7, 11, 5, 8, 12, 4, 2, 0, 14, 1, 3, 10, 9, 15, 6, 13},
    {13, 1, 7, 4, 11, 5, 0, 15, 3, 12, 14, 6, 9, 10, 2, 8},
    {5, 10, 15, 12, 1, 13, 14, 11, 8, 3, 6, 0, 4, 7, 9, 2},
    {14, 5, 0, 15, 13, 11, 3, 6, 9, 2, 12, 7, 1, 8, 10, 4},
    {11, 13, 12, 3, 7, 14, 10, 5, 0, 9, 4, 15, 2, 8, 1, 6},
    {15, 12, 9, 7, 3, 0, 11, 4, 1, 14, 2, 13, 6, 10, 8, 5}
};

inline uint32_t rotateLeft(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

uint32_t G(uint32_t a, uint32_t k) {
    uint32_t t = rotateLeft(a + k, 11);
    uint32_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= static_cast<uint32_t>(SBOX[i][(t >> (4 * i)) & 0xF]) << (4 * i);
    }
    return result;
}

std::vector<uint32_t> generateRoundKeys(const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes (256-bit)");
    std::vector<uint32_t> base_keys(8);
    for (int i = 0; i < 8; ++i) {
        base_keys[i] = (key[i*4] << 24) | (key[i*4 + 1] << 16) | (key[i*4 + 2] << 8) | key[i*4 + 3];
    }
    std::vector<uint32_t> schedule;
    schedule.insert(schedule.end(), base_keys.begin(), base_keys.end());
    schedule.insert(schedule.end(), base_keys.begin(), base_keys.end());
    schedule.insert(schedule.end(), base_keys.begin(), base_keys.end());
    schedule.insert(schedule.end(), base_keys.rbegin(), base_keys.rend());
    return schedule;
}

std::vector<uint8_t> processBlock(const std::vector<uint8_t>& block, const std::vector<uint32_t>& round_keys, bool decrypt) {
    uint32_t L = (block[0]<<24)|(block[1]<<16)|(block[2]<<8)|block[3];
    uint32_t R = (block[4]<<24)|(block[5]<<16)|(block[6]<<8)|block[7];
    for (int i = 0; i < 32; ++i) {
        int idx = decrypt ? 31 - i : i;
        uint32_t tmp = R;
        R = L ^ G(R, round_keys[idx]);
        L = tmp;
    }
    return {
        static_cast<uint8_t>((R >> 24) & 0xFF), static_cast<uint8_t>((R >> 16) & 0xFF),
        static_cast<uint8_t>((R >> 8) & 0xFF), static_cast<uint8_t>(R & 0xFF),
        static_cast<uint8_t>((L >> 24) & 0xFF), static_cast<uint8_t>((L >> 16) & 0xFF),
        static_cast<uint8_t>((L >> 8) & 0xFF), static_cast<uint8_t>(L & 0xFF)
    };
}

std::vector<uint8_t> applyPKCS7Padding(const std::vector<uint8_t>& data, size_t block_size) {
    size_t pad_len = block_size - (data.size() % block_size);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

std::vector<uint8_t> removePKCS7Padding(const std::vector<uint8_t>& data) {
    if (data.empty()) throw std::runtime_error("Empty data for unpadding");
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > data.size()) throw std::runtime_error("Invalid padding");
    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len) throw std::runtime_error("Invalid PKCS#7 padding");
    }
    return std::vector<uint8_t>(data.begin(), data.end() - pad_len);
}

void processFile(const std::string& input_file, const std::string& output_file, const std::vector<uint8_t>& key, bool decrypt) {
    auto round_keys = generateRoundKeys(key);
    std::ifstream in(input_file, std::ios::binary);
    std::ofstream out(output_file, std::ios::binary);
    if (!in || !out) throw std::runtime_error("Cannot open input or output file");
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)), {});
    if (!decrypt) buffer = applyPKCS7Padding(buffer, 8);

    for (size_t i = 0; i < buffer.size(); i += 8) {
        std::vector<uint8_t> block(buffer.begin() + i, buffer.begin() + i + 8);
        auto result = processBlock(block, round_keys, decrypt);
        out.write(reinterpret_cast<char*>(result.data()), 8);
    }

    if (decrypt) {
        out.seekp(-8, std::ios::end);
        std::vector<uint8_t> last_block(8);
        out.read(reinterpret_cast<char*>(last_block.data()), 8);
        auto unpadded = removePKCS7Padding(last_block);
        out.seekp(-8, std::ios::end);
        out.write(reinterpret_cast<char*>(unpadded.data()), unpadded.size());
        out.close();
        std::filesystem::resize_file(output_file, out.tellp());
    }
}
