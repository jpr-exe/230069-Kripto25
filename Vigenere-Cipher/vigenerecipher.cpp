#include <iostream>
#include <string>
using namespace std;

string generateKey(string text, string key) {
    int x = text.size();
    for (int i = 0; ; i++) {
        if (key.size() == text.size())
            break;
        key.push_back(key[i % key.size()]);
    }
    return key;
}

string vigenereEncrypt(string text, string key) {
    string cipher = "";
    for (int i = 0; i < text.size(); i++) {
        char x = (text[i] + key[i]) % 26;
        x += 'A';
        cipher.push_back(x);
    }
    return cipher;
}

string vigenereDecrypt(string cipher, string key) {
    string orig = "";
    for (int i = 0; i < cipher.size(); i++) {
        char x = (cipher[i] - key[i] + 26) % 26;
        x += 'A';
        orig.push_back(x);
    }
    return orig;
}

int main() {
    string text, key;
    cout << "Masukkan plaintext (HURUF BESAR): ";
    cin >> text;
    cout << "Masukkan key (HURUF BESAR): ";
    cin >> key;

    string genKey = generateKey(text, key);
    string cipher = vigenereEncrypt(text, genKey);
    string decrypt = vigenereDecrypt(cipher, genKey);

    cout << "\n=== Vigenere Cipher ===" << endl;
    cout << "Plaintext  : " << text << endl;
    cout << "Key        : " << genKey << endl;
    cout << "Ciphertext : " << cipher << endl;
    cout << "Dekripsi   : " << decrypt << endl;

    return 0;
}
