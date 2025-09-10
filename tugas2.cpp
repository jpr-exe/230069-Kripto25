#include <iostream>
#include <string>
using namespace std;

// Modulus global untuk alfabet
const int MOD = 26;

// Fungsi untuk konversi huruf ke angka (A=0, B=1, ..., Z=25)
int charToInt(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    return 0;
}

// Fungsi konversi angka ke huruf
char intToChar(int x) {
    return char((x % MOD + MOD) % MOD + 'A');
}

// Hitung determinan 2x2
int determinant(int key[2][2]) {
    return (key[0][0] * key[1][1] - key[0][1] * key[1][0]) % MOD;
}

// Cari invers modulo (Extended Euclidean Algorithm)
int modInverse(int a, int m) {
    a = (a % m + m) % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) return x;
    }
    return -1; // Tidak ada invers
}

// Cari matriks invers 2x2 (mod 26)
bool inverseKey(int key[2][2], int invKey[2][2]) {
    int det = determinant(key);
    int invDet = modInverse(det, MOD);
    if (invDet == -1) return false; // Tidak ada invers

    invKey[0][0] = ( key[1][1] * invDet) % MOD;
    invKey[0][1] = (-key[0][1] * invDet) % MOD;
    invKey[1][0] = (-key[1][0] * invDet) % MOD;
    invKey[1][1] = ( key[0][0] * invDet) % MOD;

    // Normalisasi agar positif
    for (int i=0;i<2;i++) {
        for (int j=0;j<2;j++) {
            invKey[i][j] = (invKey[i][j] % MOD + MOD) % MOD;
        }
    }
    return true;
}

// Fungsi enkripsi Hill Cipher (2x2 key)
string encrypt(string plaintext, int key[2][2]) {
    string ciphertext = "";
    if (plaintext.length() % 2 != 0) plaintext += "X"; // padding

    for (size_t i = 0; i < plaintext.length(); i += 2) {
        int p1 = charToInt(plaintext[i]);
        int p2 = charToInt(plaintext[i+1]);

        int c1 = (key[0][0]*p1 + key[0][1]*p2) % MOD;
        int c2 = (key[1][0]*p1 + key[1][1]*p2) % MOD;

        ciphertext += intToChar(c1);
        ciphertext += intToChar(c2);
    }
    return ciphertext;
}

// Fungsi dekripsi Hill Cipher
string decrypt(string ciphertext, int key[2][2]) {
    string plaintext = "";
    int invKey[2][2];
    if (!inverseKey(key, invKey)) {
        return "Kunci tidak dapat diinvers, dekripsi gagal!";
    }

    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        int c1 = charToInt(ciphertext[i]);
        int c2 = charToInt(ciphertext[i+1]);

        int p1 = (invKey[0][0]*c1 + invKey[0][1]*c2) % MOD;
        int p2 = (invKey[1][0]*c1 + invKey[1][1]*c2) % MOD;

        plaintext += intToChar(p1);
        plaintext += intToChar(p2);
    }
    return plaintext;
}

// Fungsi mencari kunci dari pasangan plaintext-ciphertext (2 huruf → 2 huruf)
bool findKey(string plain, string cipher, int key[2][2]) {
    if (plain.length() != 2 || cipher.length() != 2) return false;

    int p1 = charToInt(plain[0]);
    int p2 = charToInt(plain[1]);
    int c1 = charToInt(cipher[0]);
    int c2 = charToInt(cipher[1]);

    // Matriks plaintext (kolom)
    int P[2][2] = {{p1, p2}, {p2, p1}}; // Sederhana contoh

    // Matriks ciphertext (kolom)
    int C[2][2] = {{c1, c2}, {c2, c1}};

    // Untuk kesederhanaan contoh: asumsikan key = C * P^-1
    int invP[2][2];
    if (!inverseKey(P, invP)) return false;

    // Kalikan matriks: key = C * invP
    for (int i=0;i<2;i++) {
        for (int j=0;j<2;j++) {
            key[i][j] = 0;
            for (int k=0;k<2;k++) {
                key[i][j] += C[i][k]*invP[k][j];
            }
            key[i][j] = (key[i][j] % MOD + MOD) % MOD;
        }
    }
    return true;
}

// Fungsi input
void inputKey(int key[2][2]) {
    cout << "Masukkan matriks kunci 2x2 (elemen integer):\n";
    for (int i=0;i<2;i++) {
        for (int j=0;j<2;j++) {
            cin >> key[i][j];
        }
    }
}

// Fungsi output kunci
void printKey(int key[2][2]) {
    cout << "Matriks kunci:\n";
    for (int i=0;i<2;i++) {
        for (int j=0;j<2;j++) {
            cout << key[i][j] << " ";
        }
        cout << endl;
    }
}

int main() {
    int key[2][2];
    string text;

    cout << "=== Hill Cipher (2x2) ===\n";
    cout << "1. Enkripsi\n2. Dekripsi\n3. Cari Kunci\nPilih: ";
    int pilihan;
    cin >> pilihan;

    if (pilihan == 1) {
        inputKey(key);
        cout << "Masukkan plaintext: ";
        cin >> text;
        string cipher = encrypt(text, key);
        cout << "Ciphertext: " << cipher << endl;
    }
    else if (pilihan == 2) {
        inputKey(key);
        cout << "Masukkan ciphertext: ";
        cin >> text;
        string plain = decrypt(text, key);
        cout << "Plaintext: " << plain << endl;
    }
    else if (pilihan == 3) {
        string plain, cipher;
        cout << "Masukkan plaintext (2 huruf): ";
        cin >> plain;
        cout << "Masukkan ciphertext (2 huruf): ";
        cin >> cipher;
        if (findKey(plain, cipher, key)) {
            printKey(key);
        } else {
            cout << "Gagal menemukan kunci!\n";
        }
    }
    else {
        cout << "Pilihan tidak valid!\n";
    }

    return 0;
}
