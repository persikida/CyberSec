#include "magma_cipher.h"
#include <iostream>
#include <cassert>

void testEncryptionDecryption() {
    std::vector<uint8_t> key(32, 0x01); // простой ключ
    std::vector<uint8_t> plaintext = { 'H', 'e', 'l', 'l', 'o', '1', '2', '3' };

    auto round_keys = generateRoundKeys(key);
    auto ciphertext = processBlock(plaintext, round_keys, false);
    auto decrypted = processBlock(ciphertext, round_keys, true);

    assert(decrypted == plaintext);
    std::cout << "[PASS] Block encryption/decryption test" << std::endl;
}

void testPKCS7Padding() {
    std::vector<uint8_t> data = { 'T', 'E', 'S', 'T' };
    size_t block_size = 8;

    auto padded = applyPKCS7Padding(data, block_size);
    assert(padded.size() == 8);
    for (size_t i = 4; i < 8; ++i) assert(padded[i] == 4);

    auto unpadded = removePKCS7Padding(padded);
    assert(unpadded == data);

    std::cout << "[PASS] PKCS#7 padding/unpadding test" << std::endl;
}

int main() {
    testEncryptionDecryption();
    testPKCS7Padding();
    std::cout << "All tests passed.\n";
    return 0;
}
