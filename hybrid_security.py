from ecdsa import SigningKey, VerifyingKey, SECP256k1
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

# 1. Generate Kunci ECDSA
ecdsa_private_key = SigningKey.generate(curve=SECP256k1)
ecdsa_public_key = ecdsa_private_key.get_verifying_key()

# 2. Generate Kunci PQC (Dilithium)
pqc_public_key, pqc_private_key = generate_keypair()

# 3. Buat Pesan
message = b"Blockchain Hybrid Security!"

# 4. Tanda Tangani dengan ECDSA
ecdsa_signature = ecdsa_private_key.sign(message)

# 5. Tanda Tangani dengan Dilithium
pqc_signature = sign(message, pqc_private_key)

# 6. Verifikasi Tanda Tangan
try:
    assert ecdsa_public_key.verify(ecdsa_signature, message)
    verify(message, pqc_signature, pqc_public_key)
    print("✅ Mode Hybrid: ECDSA + PQC Valid!")
except:
    print("❌ Verifikasi Gagal!")
