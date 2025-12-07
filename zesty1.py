import zlib
import hashlib
from Crypto.Cipher import AES

def xor_b(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

def pad16(b):
    return b + b'\x00' * (-len(b) % 16)

def unpad16(b):
    # Remove null padding
    return b.rstrip(b'\x00')

# Given values
c_1_hex = "027f737775a781a3c1bda748a9af0bef"
enc_iv_hex = "ae77bc3e978a1acde6f468823d7d0e21ecaa3f00369714d0e1c9ed66945e4770823c820b5ace7f0e8c94d4b92906bce3"

c_1 = bytes.fromhex(c_1_hex)
enc_iv = bytes.fromhex(enc_iv_hex)

k_0 = b"CURTIN_CTF2025"
p = b"Favourite energy drink?........."

# Known plaintext block (second block)
p_1 = p[16:32]

print("Brute forcing k_1 (2 bytes = 65536 possibilities)...")

# Brute force k_1 (2 bytes = 65536 possibilities)
for i in range(65536):
    if i % 1000 == 0:
        print(f"Progress: {i}/65536")
    
    k_1 = i.to_bytes(2, 'big')
    key = k_0 + k_1
    
    try:
        # Try to decrypt enc_iv
        cipher_ecb = AES.new(key, AES.MODE_ECB)
        decrypted = cipher_ecb.decrypt(enc_iv)
        
        # Remove padding
        decrypted_unpadded = unpad16(decrypted)
        
        # Try to decompress
        try:
            decompressed = zlib.decompress(decrypted_unpadded)
            
            # The format is: R_P + (IV XOR hash) + R_P
            # We need to extract the IV XOR hash part
            # R_P is random, but we know the structure
            
            # The decompressed data is: R_P + (IV XOR hash) + R_P
            # R_P can be 0-15 bytes (from os.urandom(1)[0] % 16)
            # So total length is: 2*len(R_P) + 16
            
            hash_digest = hashlib.sha256(p).digest()[:16]
            
            # Try different lengths for R_P (0 to 15 bytes)
            for rp_len in range(16):
                if len(decompressed) < 2 * rp_len + 16:
                    continue
                
                # Check if first R_P matches last R_P
                if decompressed[:rp_len] == decompressed[-rp_len:]:
                    # Extract the middle part (IV XOR hash)
                    iv_xor_hash = decompressed[rp_len:rp_len+16]
                    
                    if len(iv_xor_hash) == 16:
                        # Recover IV
                        _iv = xor_b(iv_xor_hash, hash_digest)
                        
                        # Verify by encrypting with this IV
                        cipher_cbc = AES.new(key, AES.MODE_CBC, _iv)
                        ct = cipher_cbc.encrypt(p)
                        
                        # Check if c_1 matches
                        if ct[16:32] == c_1:
                            print(f"\nFound key!")
                            print(f"k_1: {k_1.hex()}")
                            print(f"Full key: {key.hex()}")
                            print(f"IV (hex): {_iv.hex()}")
                            print(f"IV (ASCII): {_iv.decode('ascii', errors='ignore')}")
                            
                            # Decrypt the full ciphertext to get the flag
                            cipher_decrypt = AES.new(key, AES.MODE_CBC, _iv)
                            decrypted_flag = cipher_decrypt.decrypt(ct)
                            print(f"\nDecrypted: {decrypted_flag}")
                            print(f"Decrypted (ASCII): {decrypted_flag.decode('ascii', errors='ignore')}")
                            
                            # Common flag formats
                            print(f"\nPossible flags:")
                            print(f"  CURTIN_CTF{{{_iv.hex()}}}")
                            print(f"  CURTIN_CTF{{{_iv.decode('ascii', errors='ignore')}}}")
                            exit(0)
        except zlib.error:
            continue
    except Exception as e:
        continue

print("No solution found!")

