from zokrates_pycrypto import setup, compute_witness, generate_proof, verify_proof

# 1. Setup ZKP
pk, vk = setup()

# 2. Hitung Witness
transaction_data = 314159  # Contoh saldo akun terenkripsi
witness = compute_witness(transaction_data)

# 3. Generate Proof tanpa mengekspos data
proof = generate_proof(pk, witness)

# 4. Verifikasi Proof
is_valid = verify_proof(vk, proof)
print(f"✅ ZKP Valid: {is_valid}")
