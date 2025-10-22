import hashlib
import os

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Step 1: Plain password
password = "user123password".encode('utf-8')

print("=== 1) WITHOUT SALT (SHA-256) ===")
h1 = sha256_hash(password)
h2 = sha256_hash(password)
print(f"Hash 1: {h1}")
print(f"Hash 2: {h2}")
print("Hashes identical?", h1 == h2)
print("-" * 60)


print("=== 2) WITH SALT (SHA-256) ===")
# Generate two different random salts (as would happen for separate sign-ups or logins)
salt1 = os.urandom(16)
salt2 = os.urandom(16)

h_salted_1 = sha256_hash(salt1 + password)
h_salted_2 = sha256_hash(salt2 + password)

print(f"Salt 1 (hex): {salt1.hex()}")
print(f"Salted hash 1: {h_salted_1}")
print()
print(f"Salt 2 (hex): {salt2.hex()}")
print(f"Salted hash 2: {h_salted_2}")
print("Hashes identical?", h_salted_1 == h_salted_2)
print("-" * 60)


print("=== 3) WITH PEPPER (SHA-256) ===")
# Pepper is a secret stored separately (e.g., env variable, config file).
# For demo purposes only, we'll show it here.
pepper = b"SuperSecretPepper123!"

h_peppered = sha256_hash(password + pepper)
h_salt_and_pepper = sha256_hash(salt1 + password + pepper)

print(f"Pepper (for demo): {pepper.decode()}")
print(f"Hash with pepper only: {h_peppered}")
print(f"Hash with salt1 + pepper: {h_salt_and_pepper}")
print()
print("Even if an attacker steals the database and sees salt1 and hashed(Salt1+password+pepper),")
print("they still can't crack it unless they also find the pepper (kept outside the DB).")
print("-" * 60)


print("Reminder:")
print("In real applications, use bcrypt / Argon2 / PBKDF2, which handle salting and are slow by design.")
print("This raw SHA-256 demo is for understanding the concept of salt and pepper.")