from ecdsa import NIST256p, ecdsa
from Crypto.Util.number import long_to_bytes

# Read the challenge data
with open("chall.txt", "r") as f:
    data = f.read()

# Parse the challenge data
exec(data)

# Set up the curve
curve = NIST256p
gen = curve.generator
order = gen.order()

# Verify the generator matches (optional check)
assert gen.x() == Gx
assert gen.y() == Gy

# Create the public point
from ecdsa.ellipticcurve import Point
pub_point = Point(curve.curve, Px, Py, order)

# ECDSA signature verification equations:
# s = k^(-1) * (m + r*d) mod n
# Rearranging: d = r^(-1) * (s*k - m) mod n

# Recover private key from signature 1
# d = r1^(-1) * (s1*n1 - m1) mod order
r1_inv = pow(r1, -1, order)
private_key_1 = (r1_inv * (s1 * n1 - m1)) % order

# Recover private key from signature 2 (for verification)
r2_inv = pow(r2, -1, order)
private_key_2 = (r2_inv * (s2 * n2 - m2)) % order

# Both should give the same private key
print(f"Private key from sig1: {private_key_1}")
print(f"Private key from sig2: {private_key_2}")

# Verify the private key is correct by checking if it generates the public key
gen_point = gen * private_key_1
print(f"\nGenerated public point: ({gen_point.x()}, {gen_point.y()})")
print(f"Expected public point: ({Px}, {Py})")
assert gen_point.x() == Px and gen_point.y() == Py, "Private key verification failed!"

# Convert private key to bytes to get the flag
flag = long_to_bytes(private_key_1)
print(f"\nFlag: {flag.decode('utf-8', errors='ignore')}")
print(f"Flag (hex): {flag.hex()}")


