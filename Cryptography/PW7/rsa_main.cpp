#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <iostream>
#include <random>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace boost::multiprecision;
using namespace std;

using BigInt = cpp_int;

// Генератор случайных чисел (глобально)
mt19937_64 gen(random_device{}());
std::uniform_int_distribution<uint64_t> dist64(0, UINT64_MAX);

// Быстрое возведение в степень по модулю
BigInt mod_pow(BigInt base, BigInt exp, const BigInt& mod) {
    BigInt result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

// Тест Ферма на простоту
bool is_prime(const BigInt& n, int k = 5) {
    if (n <= 1) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;

    for (int i = 0; i < k; ++i) {
        BigInt a = 2 + dist64(gen) % (n - 3);
        if (mod_pow(a, n - 1, n) != 1)
            return false;
    }
    return true;
}

// Генерация случайного BigInt заданной битовой длины
BigInt generate_random_bits(int bits) {
    BigInt result = 0;
    for (int i = 0; i < bits; ++i) {
        if (dist64(gen) & 1)
            result |= (BigInt(1) << i);
    }
    result |= (BigInt(1) << (bits - 1));  // устанавливаем старший бит
    return result;
}

// Генерация простого числа
BigInt generate_prime(int bits) {
    while (true) {
        BigInt candidate = generate_random_bits(bits);
        if (candidate % 2 == 0)
            ++candidate;
        if (is_prime(candidate))
            return candidate;
    }
}

// Расширенный алгоритм Евклида
BigInt extended_gcd(BigInt a, BigInt b, BigInt& x, BigInt& y) {
    if (a == 0) {
        x = 0; y = 1;
        return b;
    }
    BigInt x1, y1;
    BigInt gcd = extended_gcd(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return gcd;
}

// Обратное по модулю
BigInt mod_inverse(const BigInt& e, const BigInt& phi) {
    BigInt x, y;
    BigInt g = extended_gcd(e, phi, x, y);
    if (g != 1)
        throw runtime_error("Обратный элемент не существует");
    return (x % phi + phi) % phi;
}

// Генерация ключей RSA
pair<pair<BigInt, BigInt>, pair<BigInt, BigInt>> generate_keypair(int bits) {
    BigInt p = generate_prime(bits / 2);
    BigInt q = generate_prime(bits / 2);
    while (p == q)
        q = generate_prime(bits / 2);

    BigInt n = p * q;
    BigInt phi = (p - 1) * (q - 1);

    BigInt e = 65537;
    if (gcd(e, phi) != 1) {
        for (BigInt i = 3; i < phi; i += 2) {
            if (gcd(i, phi) == 1) {
                e = i;
                break;
            }
        }
    }

    BigInt d = mod_inverse(e, phi);
    return {{e, n}, {d, n}};
}

// Добавление паддинга (PKCS#7)
vector<uint8_t> add_padding(const vector<uint8_t>& data, size_t block_size) {
    size_t pad_len = block_size - (data.size() % block_size);
    vector<uint8_t> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

// Удаление паддинга
vector<uint8_t> remove_padding(const vector<uint8_t>& data) {
    if (data.empty()) return data;
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > data.size())
        throw runtime_error("Некорректный паддинг");
    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len)
            throw runtime_error("Некорректный паддинг");
    }
    return vector<uint8_t>(data.begin(), data.end() - pad_len);
}

// Шифрование одного блока
BigInt encrypt_block(BigInt m, const BigInt& e, const BigInt& n) {
    if (m >= n) throw runtime_error("Блок сообщения больше модуля n");
    return mod_pow(m, e, n);
}

// Расшифрование одного блока
BigInt decrypt_block(BigInt c, const BigInt& d, const BigInt& n) {
    if (c >= n) throw runtime_error("Блок шифра больше модуля n");
    return mod_pow(c, d, n);
}

// Обработка файла (encrypt/decrypt)
void process_file(const string& input_file, const string& output_file, const pair<BigInt, BigInt>& key, const string& mode) {
    BigInt exp = key.first;
    BigInt n = key.second;
    using boost::multiprecision::msb;

    size_t block_size = msb(n) / 8;
    size_t cipher_size = (msb(n) + 7) / 8;

    ifstream in(input_file, ios::binary);
    ofstream out(output_file, ios::binary);

    vector<uint8_t> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    vector<uint8_t> result;

    if (mode == "encrypt") {
        data = add_padding(data, block_size);
        for (size_t i = 0; i < data.size(); i += block_size) {
            BigInt m = 0;
            for (size_t j = 0; j < block_size; ++j)
                m = (m << 8) + data[i + j];
            BigInt c = encrypt_block(m, exp, n);
            for (int i = cipher_size - 1; i >= 0; --i)
                result.push_back(static_cast<uint8_t>((c >> (8 * i)) & 0xFF));
        }
    } else {
        if (data.size() % cipher_size != 0)
            throw runtime_error("Некратный размер шифртекста");
        vector<uint8_t> temp;
        for (size_t i = 0; i < data.size(); i += cipher_size) {
            BigInt c = 0;
            for (size_t j = 0; j < cipher_size; ++j)
                c = (c << 8) + data[i + j];
            BigInt m = decrypt_block(c, exp, n);
            vector<uint8_t> block(block_size);
            for (int j = block_size - 1; j >= 0; --j) {
                block[j] = static_cast<uint8_t>(m & 0xFF);
                m >>= 8;
            }
            temp.insert(temp.end(), block.begin(), block.end());
        }
        result = remove_padding(temp);
    }

    out.write(reinterpret_cast<char*>(result.data()), result.size());
}

// Точка входа
int main() {
    cout << "Выберите действие (generate/encrypt/decrypt): ";
    string action;
    cin >> action;

    if (action == "generate") {
        cout << "Введите битовую длину ключа (например, 512): ";
        int bits;
        cin >> bits;
        auto [pub, priv] = generate_keypair(bits);
        cout << "Публичный ключ: e=" << pub.first << ", n=" << pub.second << endl;
        cout << "Приватный ключ: d=" << priv.first << ", n=" << priv.second << endl;
        return 0;
    }

    string input_file, output_file;
    cout << "Введите входной файл: ";
    cin >> input_file;
    cout << "Введите выходной файл: ";
    cin >> output_file;

    BigInt exp, n;
    cout << "Введите ключ (exp и n через пробел): ";
    cin >> exp >> n;

    try {
        process_file(input_file, output_file, {exp, n}, action);
        cout << "Готово. Результат в " << output_file << endl;
    } catch (exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
    }

    return 0;
}