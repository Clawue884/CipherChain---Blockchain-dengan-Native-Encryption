from pympc import SecretSharing, MPC

# 1. Inisialisasi Secure MPC
mpc = MPC(num_parties=3)  # 3 pihak dalam transaksi

# 2. Bagikan Data Transaksi secara Terenkripsi
secret_transaction = SecretSharing.share(1000)  # Transfer 1000 Pi Coin

# 3. Eksekusi Transaksi tanpa mengekspos data
secure_result = mpc.compute(lambda x: x * 2, secret_transaction)

# 4. Rekonstruksi Hasil
final_result = SecretSharing.reconstruct(secure_result)

print(f"🔒 Hasil Transaksi MPC: {final_result}")
