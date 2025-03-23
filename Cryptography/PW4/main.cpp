// main.cpp
#include "magma_cipher.h"
#include <iostream>
#include <sstream>

int main() {
    std::string mode, input_file, output_file, hexkey;
    std::cout << "Mode (encrypt/decrypt): ";
    std::cin >> mode;
    std::cout << "Input file: "; std::cin >> input_file;
    std::cout << "Output file: "; std::cin >> output_file;
    std::cout << "Key (64 hex chars): "; std::cin >> hexkey;

    if (hexkey.size() != 64) {
        std::cerr << "Invalid key length!\n";
        return 1;
    }

    std::vector<uint8_t> key;
    for (size_t i = 0; i < hexkey.size(); i += 2) {
        int byte = std::stoi(hexkey.substr(i, 2), nullptr, 16);
        key.push_back(static_cast<uint8_t>(byte));
    }

    try {
        processFile(input_file, output_file, key, mode == "decrypt");
        std::cout << "Operation completed.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
