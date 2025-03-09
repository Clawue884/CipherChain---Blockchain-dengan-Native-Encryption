from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt

# 1. Generate kunci publik & privat
public_key, private_key = generate_keypair()

# 2. Enkripsi data menggunakan Kyber
ciphertext, shared_secret_enc = encrypt(public_key)

# 3. Dekripsi data dengan kunci privat
shared_secret_dec = decrypt(ciphertext, private_key)

# 4. Verifikasi integritas data
assert shared_secret_enc == shared_secret_dec, "Enkripsi/Dekripsi Gagal!"

print("🔒 Kyber PQC: Enkripsi & Dekripsi Berhasil dengan Keamanan Tahan-Kuantum!")
