from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

# 1. Generate kunci publik & privat
public_key, private_key = generate_keypair()

# 2. Buat pesan untuk ditandatangani
message = b"Transaksi Blockchain Quantum-Secure!"

# 3. Tanda tangani pesan menggunakan Dilithium
signature = sign(message, private_key)

# 4. Verifikasi tanda tangan
try:
    verify(message, signature, public_key)
    print("✅ Tanda Tangan Dilithium Valid!")
except:
    print("❌ Tanda Tangan Tidak Valid!")
