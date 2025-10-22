import os, base64, hmac, hashlib, struct, time, urllib.parse

# 1) Secret generation 
secret_bytes = os.urandom(20)
secret_b32 = base64.b32encode(secret_bytes).decode('utf-8').replace('=', '')

account_name = "ana@example.com"    
issuer = "NSSec Demo"
period = 30
digits = 6
algo = "SHA1"

# 2) otpauth provisioning URI 
label = urllib.parse.quote(f"{issuer}:{account_name}")
params = {
    "secret": secret_b32,
    "issuer": issuer,
    "period": str(period),
    "digits": str(digits),
    "algorithm": algo,
}
query = urllib.parse.urlencode(params)
otpauth_uri = f"otpauth://totp/{label}?{query}"

# 3) Try pyotp 
try:
    import pyotp  # type: ignore
    totp = pyotp.TOTP(secret_b32, interval=period, digits=digits)
    current_code_pyotp = totp.now()
except Exception:
    totp = None
    current_code_pyotp = None

def totp_code(secret_b32: str, for_time: int, period: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP using HMAC-SHA1."""
    key = base64.b32decode(secret_b32 + '=' * ((8 - len(secret_b32) % 8) % 8))
    counter = int(for_time // period)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = ((h[offset] & 0x7F) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | (h[offset+3])
    return str(code_int % (10 ** digits)).zfill(digits)

now = int(time.time())
current_code_fallback = totp_code(secret_b32, now, period, digits)

# 4) Create QR image,else write URI to a text file
qr_path = None
try:
    import qrcode  # type: ignore
    img = qrcode.make(otpauth_uri)
    qr_path = "totp_qr.png"
    img.save(qr_path)
except Exception:
    with open("totp_uri.txt", "w", encoding="utf-8") as f:
        f.write(otpauth_uri)

# 5) Print summary and preview of codes
def preview_codes(secret_b32: str, start_time: int, steps: int = 3, period: int = 30):
    rows = []
    for i in range(steps):
        t = start_time + i * period
        rows.append((i, t, totp_code(secret_b32, t, period, digits)))
    return rows

print("TOTP DEMO")
print("-" * 60)
print("Secret (Base32):", secret_b32)
print("otpauth URI:", otpauth_uri)
if totp:
    print("[pyotp] Current TOTP:", current_code_pyotp)
print("[fallback] Current TOTP:", current_code_fallback)
print("-" * 60)
for row in preview_codes(secret_b32, now):
    print("Step:", row[0], "Unix:", row[1], "Code:", row[2])

if qr_path:
    print("-" * 60)
    print("QR code image written to:", qr_path)
else:
    print("-" * 60)
    print("No QR library; wrote URI to totp_uri.txt — you can generate a QR from that.")