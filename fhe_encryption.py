from pySEAL import EncryptionParameters, SEALContext, KeyGenerator, Encryptor, Evaluator, Decryptor

# 1. Setup Parameter FHE
parms = EncryptionParameters("BFV")
parms.set_poly_modulus_degree(4096)
parms.set_coeff_modulus(SEALContext.get_default_coeff_modulus(4096))
parms.set_plain_modulus(1024)

context = SEALContext(parms)
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()

# 2. Enkripsi Data Transaksi
encryptor = Encryptor(context, public_key)
cipher_text = encryptor.encrypt(42)  # Contoh transaksi (angka 42)

# 3. Eksekusi Operasi tanpa Dekripsi
evaluator = Evaluator(context)
cipher_text_squared = evaluator.square(cipher_text)  # Perhitungan tetap terenkripsi

# 4. Dekripsi Data
decryptor = Decryptor(context, secret_key)
result = decryptor.decrypt(cipher_text_squared)

print(f"🔒 Hasil Enkripsi FHE: {result}")
