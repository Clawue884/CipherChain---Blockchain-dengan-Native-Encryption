from pqcrypto.sign.falcon512 import generate_keypair, sign, verify

# 1. Generate kunci publik & privat
public_key, private_key = generate_keypair()

# 2. Buat pesan transaksi
message = b"Transaksi Blockchain Falcon-Secure!"

# 3. Tanda tangani pesan menggunakan Falcon
signature = sign(message, private_key)

# 4. Verifikasi tanda tangan Falcon
try:
    verify(message, signature, public_key)
    print("✅ Tanda Tangan Falcon Valid!")
except:
    print("❌ Tanda Tangan Tidak Valid!")
