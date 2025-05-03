// rsa_attack_demo.cpp — Современная C++17 реализация атаки на RSA с малыми модулями
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <cmath>
#include <utility>
#include <type_traits>

namespace RSAAttack {

using u64 = std::uint64_t;

// Расширенный алгоритм Евклида — вычисляет gcd(a,b) и коэффициенты x,y: a*x + b*y = gcd
constexpr std::tuple<u64,u64,u64> extended_gcd(u64 a, u64 b) {
    if (a == 0) {
        return {b, 0, 1};
    }
    auto [g, x1, y1] = extended_gcd(b % a, a);
    u64 x = static_cast<u64>(y1 - (b / a) * x1);
    u64 y = x1;
    return {g, x, y};
}

// Мультипликативное обратное e по модулю phi
inline std::optional<u64> modular_inverse(u64 e, u64 phi) {
    auto [g, x, y] = extended_gcd(e, phi);
    if (g != 1) return std::nullopt;
    return static_cast<u64>((x % phi + phi) % phi);
}

// Быстрое возведение в степень по модулю (экспоненцирование по модулю)
template<typename T>
constexpr T modexp(T base, T exp, T mod) {
    static_assert(std::is_unsigned_v<T>, "modexp requires unsigned type");
    T result = 1;
    base %= mod;
    while (exp) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Факторизация малого n через пробное деление
inline std::pair<u64,u64> factorize(u64 n) {
    u64 limit = static_cast<u64>(std::sqrt(n));
    for (u64 i = 2; i <= limit; ++i) {
        if (n % i == 0) {
            return {i, n / i};
        }
    }
    throw std::runtime_error("Failed to factorize n");
}

// Основной функционал атаки на RSA
inline u64 attack(u64 e, u64 n, u64 ciphertext) {
    auto [p, q] = factorize(n);
    std::cout << "Factorization: n = " << n << " = " << p << " * " << q << '\n';

    u64 phi = (p - 1) * (q - 1);
    std::cout << "phi(n) = " << phi << '\n';

    auto d_opt = modular_inverse(e, phi);
    if (!d_opt) {
        throw std::runtime_error("No modular inverse for e and phi(n)");
    }
    u64 d = *d_opt;
    std::cout << "Private exponent: d = " << d << '\n';

    u64 plaintext = modexp<u64>(ciphertext, d, n);
    std::cout << "Decrypted (number): " << plaintext << '\n';
    return plaintext;
}

} // namespace RSAAttack

int main() {
    std::cout << "=== RSA Small-n Attack Demo (C++17) ===\n";

    // Демонстрационный пример
    constexpr RSAAttack::u64 e = 7;
    constexpr RSAAttack::u64 n = 77;       // 7 * 11
    constexpr RSAAttack::u64 c = 33;      // m = 33, символ '!'

    std::cout << "Public key: e = " << e << ", n = " << n << "\n";
    std::cout << "Ciphertext: c = " << c << "\n\n";

    try {
        u64 m = RSAAttack::attack(e, n, c);
        if (m < 256) {
            char ch = static_cast<char>(m);
            std::cout << "Decrypted (char): '" << ch << "'\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
