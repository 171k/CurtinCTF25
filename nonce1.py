import json
import hashlib
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

# Load challenge data
with open("challenge.json", "r") as f:
    challenge_data = json.load(f)

with open("public.json", "r") as f:
    public_data = json.load(f)

with open("flag.enc", "rb") as f:
    encrypted_flag = f.read()

# Parse public parameters
p = int(public_data["p"])
q = int(public_data["q"])
g = int(public_data["g"])

signatures = challenge_data["signatures"]
num_parts = challenge_data["metadata"]["num_parts"]
part_len = challenge_data["metadata"]["part_len"]

def H(m_hex):
    """Hash function used in DSA"""
    m_bytes = bytes.fromhex(m_hex)
    return int(hashlib.sha1(m_bytes).hexdigest(), 16)

# Group signatures by part index
signatures_by_part = {}
for sig in signatures:
    part_idx = sig["part"]
    if part_idx != -1:
        if part_idx not in signatures_by_part:
            signatures_by_part[part_idx] = []
        signatures_by_part[part_idx].append(sig)

print(f"Found signatures for parts: {sorted(signatures_by_part.keys())}")
print(f"Number of parts: {num_parts}")
print(f"Part length: {part_len}")

# For each part, find pairs with the same r (same k)
x_parts = {}
decrypted_parts = []

for part_idx in sorted(signatures_by_part.keys()):
    sigs = signatures_by_part[part_idx]
    print(f"\n--- Part {part_idx} ---")
    print(f"Found {len(sigs)} signatures for this part")
    
    # Group by r value to find nonce reuse
    r_groups = {}
    for sig in sigs:
        r = sig["r"]
        if r not in r_groups:
            r_groups[r] = []
        r_groups[r].append(sig)
    
    # Find groups with multiple signatures (nonce reuse)
    found_pair = False
    for r, sig_list in r_groups.items():
        if len(sig_list) >= 2:
            print(f"Found {len(sig_list)} signatures with same r={r}")
            # Take first two signatures with same r
            sig1, sig2 = sig_list[0], sig_list[1]
            
            h1 = H(sig1["msg"])
            s1 = sig1["s"]
            h2 = H(sig2["msg"])
            s2 = sig2["s"]
            
            # Recover k: k = (h1 - h2) * (s1 - s2)^(-1) mod q
            s_diff = (s1 - s2) % q
            s_diff_inv = inverse(s_diff, q)
            k = ((h1 - h2) * s_diff_inv) % q
            
            # Recover x: x = (s*k - h) * r^(-1) mod q
            r_inv = inverse(r, q)
            x = ((s1 * k - h1) * r_inv) % q
            
            x_parts[part_idx] = x
            print(f"Recovered k = {k}")
            print(f"Recovered x = {x}")
            
            # Decrypt this part of the flag
            start = part_idx * part_len
            end = (part_idx + 1) * part_len
            encrypted_part = encrypted_flag[start:end]
            x_bytes = long_to_bytes(x, part_len)
            decrypted_part = bytes([a ^ b for a, b in zip(encrypted_part, x_bytes)])
            decrypted_parts.append((part_idx, decrypted_part))
            print(f"Decrypted part {part_idx}: {decrypted_part}")
            found_pair = True
            break
    
    if not found_pair:
        print(f"WARNING: Could not find a pair with same r for part {part_idx}")

# Reconstruct flag
print("\n" + "="*50)
print("Reconstructing flag...")
print("="*50)

# Sort by part index and combine
decrypted_parts.sort(key=lambda x: x[0])
flag_parts = [part for _, part in decrypted_parts]
flag = b''.join(flag_parts)

print(f"\nFull flag: {flag}")
# Remove null bytes at the end (padding)
flag_clean = flag.rstrip(b'\x00')
print(f"Flag (cleaned): {flag_clean.decode('utf-8', errors='ignore')}")
