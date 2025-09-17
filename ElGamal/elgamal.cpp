#include <iostream>
#include <string>
using namespace std;

long long modExp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp / 2;
        base = (base * base) % mod;
    }
    return result;
}

long long modInverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m; a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
        x1 += m0;
    return x1;
}

int main() {
    long long p, g, x, k; 
    
    string plaintext;
    cout << "Masukkan plaintext (HURUF BESAR): ";
    cin >> plaintext;
    cout << "Masukkan p : ";
    cin >> p;
    cout << "Masukkan g : ";
    cin >> g;
    cout << "Masukkan x : ";
    cin >> x;
    cout << "Masukkan k : ";
    cin >> k;
    long long y = modExp(g, x, p); 
    cout << "\n=== ElGamal Encryption/Decryption ===" << endl;
    cout << "p = " << p << ", g = " << g << ", x = " << x << ", k = " << k << endl;
    cout << "Public key (y) = " << y << endl;

    int n = plaintext.size();
    long long a = modExp(g, k, p);
    long long s = modExp(y, k, p);
    long long sInv = modInverse(s, p);

    cout << "\nCiphertext (a,b):" << endl;
    long long b[100];
    for (int i = 0; i < n; i++) {
        int m = plaintext[i] - 'A';
        b[i] = (m * s) % p;
        cout << "(" << a << "," << b[i] << ") ";
    }
    cout << endl;

    cout << "\nDekripsi:" << endl;
    for (int i = 0; i < n; i++) {
        long long m = (b[i] * sInv) % p;
        char ch = (char)(m + 'A');
        cout << ch;
    }
    cout << endl;

    return 0;
}
