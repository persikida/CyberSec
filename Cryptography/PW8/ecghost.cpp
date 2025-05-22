#include <iostream>
#include <fstream>
#include <optional>
#include <tuple>
#include <random>
#include <openssl/sha.h>
#include <filesystem>
#include <string>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace std;
using Point = pair<int, int>;
using OptionalPoint = optional<Point>;

tuple<int, int, int> extended_gcd(int a, int b) {
    if (a == 0) {
        return {b, 0, 1};
    }
    auto [gcd, x1, y1] = extended_gcd(b % a, a);
    int x = y1 - (b / a) * x1;
    int y = x1;
    return {gcd, x, y};
}

optional<int> mod_inverse(int a, int m) {
    auto [gcd, x, y] = extended_gcd(a, m);
    if (gcd != 1) {
        return nullopt;
    }
    return (x % m + m) % m;
}

class EllipticCurve {
private:
    int a, b, p;

public:
    EllipticCurve(int a, int b, int p) : a(a), b(b), p(p) {}

    bool is_point_on_curve(const Point& P) const {
        int x = P.first;
        int y = P.second;
        int left = (y * y) % p;
        int right = (x*x*x + a*x + b) % p;
        return left == right;
    }

    OptionalPoint add_points(const OptionalPoint& P_opt, const OptionalPoint& Q_opt) const {
        if (!P_opt.has_value()) return Q_opt;
        if (!Q_opt.has_value()) return P_opt;

        Point P = P_opt.value();
        Point Q = Q_opt.value();
        int x1 = P.first, y1 = P.second;
        int x2 = Q.first, y2 = Q.second;

        if (x1 == x2 && (y1 + y2) % p == 0) {
            return nullopt;
        }

        int lambda;
        if (P == Q) {
            if (y1 == 0) return nullopt;
            int denominator = (2 * y1) % p;
            auto inv = mod_inverse(denominator, p);
            if (!inv) return nullopt;
            lambda = ((3 * x1*x1 + a) * inv.value()) % p;
        } else {
            int denominator = (x2 - x1) % p;
            auto inv = mod_inverse(denominator, p);
            if (!inv) return nullopt;
            lambda = ((y2 - y1) * inv.value()) % p;
        }

        int x3 = (lambda*lambda - x1 - x2) % p;
        x3 = (x3 + p) % p;
        int y3 = (lambda*(x1 - x3) - y1) % p;
        y3 = (y3 + p) % p;

        return make_pair(x3, y3);
    }

    OptionalPoint multiply_point(const Point& P, int k) const {
        OptionalPoint result = nullopt;
        OptionalPoint addend = P;

        while (k > 0) {
            if (k & 1) {
                result = add_points(result, addend);
            }
            addend = add_points(addend, addend);
            k >>= 1;
        }

        return result;
    }
};

int hash_message(const string& message) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.data()), message.size(), digest);

    int result = 0;
    for (int i = 0; i < 4; ++i) {
        result = (result << 8) | digest[i];
    }
    return result;
}

pair<int, Point> generate_keypair(const EllipticCurve& curve, const Point& G, int q) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, q-1);

    while (true) {
        int d = dis(gen);
        auto Q_opt = curve.multiply_point(G, d);
        if (Q_opt.has_value() && curve.is_point_on_curve(Q_opt.value())) {
            return {d, Q_opt.value()};
        }
    }
}

pair<int, int> sign_message(const string& message, const EllipticCurve& curve, const Point& G, int q, int d) {
    int h = hash_message(message);
    int e = h % q;
    if (e == 0) e = 1;

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, q-1);

    while (true) {
        int k = dis(gen);
        auto P_opt = curve.multiply_point(G, k);
        if (!P_opt) continue;

        int r = P_opt->first % q;
        if (r == 0) continue;

        int s = (r * d + k * e) % q;
        if (s == 0) continue;

        return {r, s};
    }
}

bool verify_signature(const string& message, const pair<int, int>& signature, 
                     const EllipticCurve& curve, const Point& G, int q, const Point& Q) {
    auto [r, s] = signature;

    if (r <= 0 || r >= q || s <= 0 || s >= q) return false;
    if (!curve.is_point_on_curve(Q)) return false;

    int h = hash_message(message);
    int e = h % q;
    if (e == 0) e = 1;

    auto v_opt = mod_inverse(e, q);
    if (!v_opt) return false;
    int v = v_opt.value();

    int z1 = (s * v) % q;
    int z2 = (-r * v) % q;
    z2 = (z2 + q) % q;

    auto P1 = curve.multiply_point(G, z1);
    auto P2 = curve.multiply_point(Q, z2);
    auto C = curve.add_points(P1, P2);

    if (!C) return false;
    return (C->first % q + q) % q == r;
}

void process_file(const string& input_file, const string& output_file, 
                 const EllipticCurve& curve, const Point& G, int q,
                 const pair<int, Point>& key, const string& mode) {
    if (!filesystem::exists(input_file)) {
        throw runtime_error("File not found: " + input_file);
    }

    ifstream in(input_file, ios::binary);
    string msg((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    if (mode == "sign") {
        auto [d, _] = key;
        auto [r, s] = sign_message(msg, curve, G, q, d);
        ofstream out(output_file);
        out << r << " " << s;
        out.close();
    } else {
        if (!filesystem::exists(output_file)) {
            throw runtime_error("Signature file not found: " + output_file);
        }
        ifstream sig_file(output_file);
        int r, s;
        sig_file >> r >> s;
        sig_file.close();

        auto [_, Q] = key;
        bool ok = verify_signature(msg, {r, s}, curve, G, q, Q);
        ofstream result("verify_result.txt");
        result << (ok ? "Подпись верна" : "Подпись неверна");
        result.close();
    }
}

int main() {
    int p = 17, a = 2, b = 2, q = 19;
    EllipticCurve curve(a, b, p);
    Point G = {5, 1};

    cout << "ГОСТ Р 34.10-2012 (C++ реализация)\n";
    string mode;
    while (true) {
        cout << "Выберите операцию (generate/sign/verify): ";
        cin >> mode;
        if (mode == "generate" || mode == "sign" || mode == "verify") break;
        cout << "Некорректный режим!\n";
    }

    if (mode == "generate") {
        auto [d, Q] = generate_keypair(curve, G, q);
        cout << "Секретный ключ: " << d << "\nПубличный ключ: (" 
             << Q.first << ", " << Q.second << ")\n";
        return 0;
    }

    string msg_file, sig_file;
    cout << "Файл сообщения: "; cin >> msg_file;
    cout << "Файл подписи: "; cin >> sig_file;

    if (mode == "sign") {
        int d;
        cout << "Секретный ключ: "; cin >> d;
        process_file(msg_file, sig_file, curve, G, q, {d, {}}, "sign");
        cout << "Подпись создана\n";
    } else {
        int x, y;
        cout << "Публичный ключ (x y): "; cin >> x >> y;
        process_file(msg_file, sig_file, curve, G, q, {0, {x, y}}, "verify");
        
        ifstream result("verify_result.txt");
        string res;
        getline(result, res);
        cout << "Результат: " << res << endl;
    }

    return 0;
}