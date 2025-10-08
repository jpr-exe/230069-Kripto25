# stego_enhanced_lsb.py
# Program encode/decode steganography (enhanced LSB) dengan variabel berbahasa Indonesia

import os
import sys
import math
import hashlib
import random
from tkinter import Tk, filedialog, simpledialog, messagebox
from PIL import Image

# ========== utilitas bit ==========
def ambil_bit(bait, posisi):
    # ambil bit pada posisi (0 = LSB)
    return (bait >> posisi) & 1

def set_bit(bait, posisi, nilai):
    # set bit pada posisi (0 = LSB) ke 0/1
    if nilai:
        return bait | (1 << posisi)
    else:
        return bait & ~(1 << posisi)

# ========== enkripsi sederhana (XOR stream) ==========
def buat_keystream(kunci, panjang):
    # buat keystream pseudo-random dari kunci (bytes)
    # gunakan SHA256 sebagai seed untuk generator
    seed = hashlib.sha256(kunci).digest()
    rnd = random.Random(int.from_bytes(seed, "big"))
    return bytes([rnd.randrange(0, 256) for _ in range(panjang)])

def xor_bytes(data, kunci):
    if not kunci:
        return data
    keystream = buat_keystream(kunci, len(data))
    return bytes([d ^ k for d, k in zip(data, keystream)])

# ========== pembentukan payload (header + data) ==========
# Format payload yang disematkan:
# 3 byte tipe: b'TXT' atau b'IMG'
# 4 byte panjang data (big-endian) -> panjang N
# jika tipe == 'IMG' -> 1 byte panjang ekstensi E, E byte ekstensi ascii (mis. b'png')
# lalu N byte data (teks encoded utf-8 untuk TXT, atau file bytes untuk IMG)
def buat_payload_teks(teks, kunci_bytes):
    data = teks.encode("utf-8")
    header = b'TXT' + len(data).to_bytes(4, "big")
    semua = header + data
    return xor_bytes(semua, kunci_bytes)

def buat_payload_gambar(path_file, kunci_bytes):
    nama = os.path.basename(path_file)
    _, ekst = os.path.splitext(nama)
    ekst = ekst.lower().lstrip('.')
    if not ekst:
        ekst = "raw"
    with open(path_file, "rb") as f:
        data = f.read()
    header = b'IMG' + len(data).to_bytes(4, "big")
    ekst_bytes = ekst.encode("ascii")
    header += len(ekst_bytes).to_bytes(1, "big") + ekst_bytes
    semua = header + data
    return xor_bytes(semua, kunci_bytes)

# ========== fungsi embed / extract enhanced LSB ==========
def hitung_kapasitas(img, jumlah_bit_lsb):
    lebar, tinggi = img.size
    total_kanal = lebar * tinggi * 3  # RGB
    return total_kanal * jumlah_bit_lsb

def embed_data_ke_gambar(img, payload_bytes, kunci_teks, jumlah_bit_lsb=1):
    # img: PIL Image (RGB)
    if img.mode != "RGB":
        img = img.convert("RGB")

    lebar, tinggi = img.size
    piksel = list(img.getdata())  # list of (r,g,b)
    total_kanal = len(piksel) * 3
    kapasitas_bit = total_kanal * jumlah_bit_lsb

    payload_bits = []
    for b in payload_bytes:
        for i in range(8):
            payload_bits.append((b >> i) & 1)  # simpan LSB first (pos 0..7)

    if len(payload_bits) > kapasitas_bit:
        raise ValueError(f"Payload terlalu besar untuk gambar pembawa. Kapasitas bit: {kapasitas_bit}, butuh: {len(payload_bits)}")

    # buat daftar posisi global (0..kapasitas_bit-1) dan shuffle dengan seed dari kunci
    seed = hashlib.sha256(kunci_teks).digest()
    rng = random.Random(int.from_bytes(seed, "big"))
    daftar_pos = list(range(kapasitas_bit))
    rng.shuffle(daftar_pos)

    # ubah piksel jadi list nilai kanal linear
    kanal = []
    for (r, g, b) in piksel:
        kanal.extend([r, g, b])

    # set bit sesuai posisi acak (gunakan bit LSB positions 0..jumlah_bit_lsb-1)
    for idx_bit, bit_nilai in enumerate(payload_bits):
        global_pos = daftar_pos[idx_bit]
        indeks_kanal = global_pos // jumlah_bit_lsb
        posisi_lsb = global_pos % jumlah_bit_lsb  # 0..(jumlah_bit_lsb-1)
        bait_lama = kanal[indeks_kanal]
        bait_baru = set_bit(bait_lama, posisi_lsb, bit_nilai)
        kanal[indeks_kanal] = bait_baru

    # recompose piksel
    piksel_baru = []
    for i in range(0, len(kanal), 3):
        piksel_baru.append((kanal[i], kanal[i+1], kanal[i+2]))

    img_baru = Image.new("RGB", (lebar, tinggi))
    img_baru.putdata(piksel_baru)
    return img_baru

def extract_payload_dari_gambar(img, kunci_teks, jumlah_bit_lsb=1):
    if img.mode != "RGB":
        img = img.convert("RGB")
    piksel = list(img.getdata())
    kanal = []
    for (r, g, b) in piksel:
        kanal.extend([r, g, b])
    total_kanal = len(kanal)
    kapasitas_bit = total_kanal * jumlah_bit_lsb

    seed = hashlib.sha256(kunci_teks).digest()
    rng = random.Random(int.from_bytes(seed, "big"))
    daftar_pos = list(range(kapasitas_bit))
    rng.shuffle(daftar_pos)

    # buat urutan bit (mengambil sampai kita bisa parse header)
    bit_stream = []
    # kita butuh minimal header 3 +4 =7 byte -> 56 bit. Untuk IMG tambahan 1+ext but kita mulai dari 64+ lebih.
    ambil_awal = min(kapasitas_bit, 8 * 1024 * 1024)  # safety limit (8M bits)
    for i in range(ambil_awal):
        global_pos = daftar_pos[i]
        indeks_kanal = global_pos // jumlah_bit_lsb
        posisi_lsb = global_pos % jumlah_bit_lsb
        if indeks_kanal >= total_kanal:
            break
        bait = kanal[indeks_kanal]
        bit = ambil_bit(bait, posisi_lsb)
        bit_stream.append(bit)

    # buat bytes dari bit_stream (LSB first per byte)
    def bits_ke_bytes(bits):
        out = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i:i+8]
            if len(chunk) < 8:
                break
            val = 0
            for j, bt in enumerate(chunk):
                val |= (bt & 1) << j
            out.append(val)
        return bytes(out)

    semua_bait_terenkripsi = bits_ke_bytes(bit_stream)

    # coba dekripsi bertahap: pertama ambil header terenkripsi, kemudian kita decrypt lebih banyak sesuai panjang
    # karena XOR stream, dekripsi memerlukan kunci. Kita punya kunci_teks (bytes).
    # Lakukan dekripsi awal sampai minimal header.
    kunci_bytes = kunci_teks
    if kunci_bytes is None:
        kunci_bytes = b""
    # decrypt awal
    awal_decrypted = xor_bytes(semua_bait_terenkripsi[:64], kunci_bytes)  # ambil 64 bytes decrypted
    # parse header jika mungkin
    if len(awal_decrypted) < 7:
        raise ValueError("Gagal membaca header. Mungkin kunci salah atau gambar tidak berisi payload.")

    tipe = awal_decrypted[0:3]
    panjang_data = int.from_bytes(awal_decrypted[3:7], "big")
    offset = 7

    ekstensi = b""
    if tipe == b'IMG':
        if len(awal_decrypted) < 8:
            # perlu lebih banyak data untuk baca panjang ekstensi
            pass
        panjang_ekstensi = awal_decrypted[7]
        # kebutuhan total header = 3 + 4 + 1 + panjang_ekstensi
        total_header_bait = 3 + 4 + 1 + panjang_ekstensi
        total_header_bit = total_header_bait * 8
        # pastikan kita punya cukup bit di bit_stream; jika belum, kembangkan
        if len(bit_stream) < total_header_bit:
            # perlu ambil lebih banyak bit dari gambar
            lebih_ambil = total_header_bit - len(bit_stream)
            for i in range(ambil_awal, ambil_awal + lebih_ambil):
                if i >= kapasitas_bit:
                    break
                global_pos = daftar_pos[i]
                indeks_kanal = global_pos // jumlah_bit_lsb
                posisi_lsb = global_pos % jumlah_bit_lsb
                bait = kanal[indeks_kanal]
                bit = ambil_bit(bait, posisi_lsb)
                bit_stream.append(bit)
            semua_bait_terenkripsi = bits_ke_bytes(bit_stream)
            awal_decrypted = xor_bytes(semua_bait_terenkripsi[:total_header_bait], kunci_bytes)
            panjang_data = int.from_bytes(awal_decrypted[3:7], "big")
            panjang_ekstensi = awal_decrypted[7]
            ekstensi = awal_decrypted[8:8+panjang_ekstensi]
            offset = 8 + panjang_ekstensi
        else:
            panjang_ekstensi = awal_decrypted[7]
            ekstensi = awal_decrypted[8:8+panjang_ekstensi]
            offset = 8 + panjang_ekstensi
    else:
        # tipe TXT, offset tetap 7
        offset = 7

    # total payload byte yang perlu diambil (header+data) => header_bait + panjang_data
    if tipe == b'IMG':
        panjang_header = 3 + 4 + 1 + len(ekstensi)
    else:
        panjang_header = 3 + 4

    total_bait_perlu = panjang_header + panjang_data
    total_bit_perlu = total_bait_perlu * 8

    if total_bit_perlu > kapasitas_bit:
        raise ValueError("Header menunjukkan payload lebih besar dari kapasitas gambar. Gagal ekstraksi.")

    # jika belum ada cukup bit, ambil sisa
    if len(bit_stream) < total_bit_perlu:
        for i in range(len(bit_stream), total_bit_perlu):
            if i >= kapasitas_bit:
                break
            global_pos = daftar_pos[i]
            indeks_kanal = global_pos // jumlah_bit_lsb
            posisi_lsb = global_pos % jumlah_bit_lsb
            bait = kanal[indeks_kanal]
            bit = ambil_bit(bait, posisi_lsb)
            bit_stream.append(bit)
        semua_bait_terenkripsi = bits_ke_bytes(bit_stream)

    semua_decrypted = xor_bytes(semua_bait_terenkripsi[:total_bait_perlu], kunci_bytes)
    # pisah header dan data
    tipe = semua_decrypted[0:3]
    panjang_data = int.from_bytes(semua_decrypted[3:7], "big")
    if tipe == b'IMG':
        panjang_ekstensi = semua_decrypted[7]
        ekstensi = semua_decrypted[8:8+panjang_ekstensi].decode("ascii", errors="ignore")
        data = semua_decrypted[8+panjang_ekstensi:8+panjang_ekstensi+panjang_data]
        return {"tipe": "IMG", "data": data, "ekstensi": ekstensi}
    elif tipe == b'TXT':
        data = semua_decrypted[7:7+panjang_data]
        try:
            teks = data.decode("utf-8")
        except:
            teks = data.decode("latin-1", errors="replace")
        return {"tipe": "TXT", "teks": teks}
    else:
        raise ValueError("Tipe payload tidak dikenal.")

# ========== antarmuka sederhana (Tkinter filedialog) ==========
def pilih_file_gambar_dialog(judul="Pilih gambar"):
    root = Tk()
    root.withdraw()
    path = filedialog.askopenfilename(title=judul,
                                      filetypes=[("Image files", "*.png *.bmp *.jpg *.jpeg *.tiff *.tif"), ("All files", "*.*")])
    root.destroy()
    return path

def simpan_file_dialog(nama_default, ekstensi_saran=None):
    root = Tk()
    root.withdraw()
    path = filedialog.asksaveasfilename(defaultextension=ekstensi_saran or "",
                                        initialfile=nama_default,
                                        title="Simpan file hasil")
    root.destroy()
    return path

def minta_input_teks(prompt="Masukkan teks"):
    # gunakan simpledialog agar tetap GUI-friendly
    root = Tk()
    root.withdraw()
    teks = simpledialog.askstring("Input", prompt)
    root.destroy()
    return teks

def minta_input_kunci(prompt="Masukkan kata sandi (digunakan sebagai seed)"):
    root = Tk()
    root.withdraw()
    kunci = simpledialog.askstring("Kunci", prompt, show="*")
    root.destroy()
    if kunci is None:
        return None
    return kunci.encode("utf-8")

def mode_menu():
    print("Pilih mode:")
    print("1. Encode teks ke gambar")
    print("2. Encode file gambar ke gambar")
    print("3. Decode dari gambar")
    pilihan = input("Masukkan pilihan (1/2/3): ").strip()
    return pilihan

def main():
    print("Steganography Enhanced LSB")
    pilihan = mode_menu()
    if pilihan not in ("1", "2", "3"):
        print("Pilihan tidak valid. Keluar.")
        return

    path_gambar = pilih_file_gambar_dialog("Pilih gambar pembawa (carrier)")
    if not path_gambar:
        print("Tidak ada file dipilih. Keluar.")
        return
    try:
        gambar = Image.open(path_gambar)
    except Exception as e:
        print("Gagal membuka gambar:", e)
        return

    jumlah_bit_lsb = 1
    try:
        teks_input = input("Jumlah bit LSB per kanal (1-3), tekan Enter untuk default 1: ").strip()
        if teks_input:
            val = int(teks_input)
            if val < 1 or val > 3:
                print("Nilai tidak valid, gunakan 1.")
            else:
                jumlah_bit_lsb = val
    except:
        jumlah_bit_lsb = 1

    kunci_bytes = minta_input_kunci()
    if kunci_bytes is None:
        print("Kunci tidak diberikan. Keluar.")
        return

    if pilihan == "1":
        # encode teks
        teks = minta_input_teks("Masukkan teks yang ingin disembunyikan")
        if teks is None:
            print("Teks tidak diberikan. Keluar.")
            return
        payload = buat_payload_teks(teks, kunci_bytes)
        kapasitas = hitung_kapasitas(gambar, jumlah_bit_lsb)
        print(f"Kapasitas (bit): {kapasitas}. Butuh (bit): {len(payload) * 8}")
        if len(payload) * 8 > kapasitas:
            print("Teks terlalu panjang untuk gambar pembawa. Pilih gambar lain atau kurangi teks.")
            return
        gambar_baru = embed_data_ke_gambar(gambar, payload, kunci_bytes, jumlah_bit_lsb)
        path_simpan = simpan_file_dialog("stego.png", ".png")
        if not path_simpan:
            print("Tidak ada lokasi simpan. Keluar.")
            return
        gambar_baru.save(path_simpan, "PNG")
        print("Selesai. File tersimpan di:", path_simpan)

    elif pilihan == "2":
        # encode file gambar ke gambar
        path_payload = pilih_file_gambar_dialog("Pilih file gambar yang akan disembunyikan")
        if not path_payload:
            print("Tidak ada file payload dipilih. Keluar.")
            return
        payload = buat_payload_gambar(path_payload, kunci_bytes)
        kapasitas = hitung_kapasitas(gambar, jumlah_bit_lsb)
        print(f"Kapasitas (bit): {kapasitas}. Butuh (bit): {len(payload) * 8}")
        if len(payload) * 8 > kapasitas:
            print("File payload terlalu besar untuk gambar pembawa. Pilih gambar lain atau kurangi ukuran payload.")
            return
        gambar_baru = embed_data_ke_gambar(gambar, payload, kunci_bytes, jumlah_bit_lsb)
        path_simpan = simpan_file_dialog("stego_with_image.png", ".png")
        if not path_simpan:
            print("Tidak ada lokasi simpan. Keluar.")
            return
        gambar_baru.save(path_simpan, "PNG")
        print("Selesai. File tersimpan di:", path_simpan)

    else:
        # decode
        try:
            hasil = extract_payload_dari_gambar(gambar, kunci_bytes, jumlah_bit_lsb)
        except Exception as e:
            print("Gagal ekstraksi:", e)
            return
        if hasil["tipe"] == "TXT":
            print("=== Pesan Teks Ditemukan ===")
            print(hasil["teks"])
            # tawarkan simpan
            simpan = input("Simpan teks ke file? (y/n): ").strip().lower()
            if simpan == "y":
                path_simpan = simpan_file_dialog("pesan_tersembunyi.txt", ".txt")
                if path_simpan:
                    with open(path_simpan, "w", encoding="utf-8") as f:
                        f.write(hasil["teks"])
                    print("Tersimpan di:", path_simpan)
        else:
            print("=== File Gambar Ditemukan ===")
            ekst = hasil.get("ekstensi", "bin")
            ukuran = len(hasil["data"])
            print(f"Ekstensi: {ekst}, ukuran: {ukuran} bytes")
            path_simpan = simpan_file_dialog(f"payload_output.{ekst}", f".{ekst}")
            if path_simpan:
                with open(path_simpan, "wb") as f:
                    f.write(hasil["data"])
                print("Tersimpan di:", path_simpan)

if __name__ == "__main__":
    main()
