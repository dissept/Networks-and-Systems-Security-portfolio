from __future__ import annotations
import os, re, hmac, base64, time, hashlib, struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


# Password strength 
def analyze_password_strength(pw: str) -> Tuple[bool, str]:
    if len(pw) < 12:
        return False, "Password too short (min 12)."
    classes = 0
    classes += bool(re.search(r"[a-z]", pw))
    classes += bool(re.search(r"[A-Z]", pw))
    classes += bool(re.search(r"[0-9]", pw))
    classes += bool(re.search(r"[^A-Za-z0-9]", pw))
    if classes < 3:
        return False, "Use at least 3 of: lowercase, uppercase, digits, symbols."
    for pat in (r"password", r"1234", r"qwerty", r"letmein"):
        if re.search(pat, pw, re.I):
            return False, "Avoid common patterns like 'password', '1234', 'qwerty'."
    return True, "OK"


# Hashing helpers
def _has_bcrypt() -> bool:
    try:
        import bcrypt  
        return True
    except Exception:
        return False

def hash_password(password: str, pepper: Optional[bytes] = None) -> str:
    pwd = password.encode("utf-8")
    if pepper:
        pwd += pepper
    if _has_bcrypt():
        import bcrypt  
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(pwd, salt).decode("utf-8")
    
    iterations = 210_000
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd, salt, iterations, dklen=32)
    return "pbkdf2${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )

def verify_password(password: str, stored: str, pepper: Optional[bytes] = None) -> bool:
    pwd = password.encode("utf-8")
    if pepper:
        pwd += pepper
    if stored.startswith("$2"):  
        import bcrypt  
        try:
            return bcrypt.checkpw(pwd, stored.encode("utf-8"))
        except Exception:
            return False
    if stored.startswith("pbkdf2$"):
        try:
            _, it_s, salt_b64, hash_b64 = stored.split("$", 3)
            iterations = int(it_s)
            salt = base64.b64decode(salt_b64.encode("ascii"))
            expected = base64.b64decode(hash_b64.encode("ascii"))
            dk = hashlib.pbkdf2_hmac("sha256", pwd, salt, iterations, dklen=32)
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False
    return False


# TOTP helpers 
def generate_totp_secret(nbytes: int = 20) -> str:
    secret = os.urandom(nbytes)
    return base64.b32encode(secret).decode("utf-8").replace("=", "")

def otpauth_uri(secret_b32: str, account: str, issuer: str, period: int = 30, digits: int = 6) -> str:
    from urllib.parse import quote, urlencode
    label = quote(f"{issuer}:{account}")
    params = urlencode({
        "secret": secret_b32, "issuer": issuer, "period": str(period),
        "digits": str(digits), "algorithm": "SHA1"
    })
    return f"otpauth://totp/{label}?{params}"

def totp_now(secret_b32: str, period: int = 30, digits: int = 6) -> str:
    try:
        import pyotp  
        return pyotp.TOTP(secret_b32, interval=period, digits=digits).now()
    except Exception:
        pass
    # (SHA1)
    key = base64.b32decode(secret_b32 + '=' * ((8 - len(secret_b32) % 8) % 8))
    counter = int(time.time() // period)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = ((h[offset] & 0x7F) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | (h[offset+3])
    return str(code_int % (10 ** digits)).zfill(digits)

def verify_totp(secret_b32: str, code: str, period: int = 30, digits: int = 6, window: int = 1) -> bool:
    key = base64.b32decode(secret_b32 + '=' * ((8 - len(secret_b32) % 8) % 8))
    def code_for(counter: int) -> str:
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code_int = ((h[offset] & 0x7F) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | (h[offset+3])
        return str(code_int % (10 ** digits)).zfill(digits)
    now_counter = int(time.time() // period)
    tgt = code.strip()
    for delta in range(-window, window+1):
        if hmac.compare_digest(code_for(now_counter + delta), tgt):
            return True
    return False


# main system 
@dataclass
class UserRecord:
    username: str
    password_hash: str
    totp_secret: str
    issuer: str = "DemoAuth"

class AuthSystem:
    def __init__(self, issuer: str = "DemoAuth", period: int = 30, digits: int = 6):
        self.issuer = issuer
        self.period = period
        self.digits = digits
        self.users: Dict[str, UserRecord] = {}
        # pepper from environment
        self.pepper: Optional[bytes] = os.getenv("AUTH_PEPPER", "").encode("utf-8") or None

    def register_user(self, username: str, password: str, account_name_for_totp: Optional[str] = None):
        ok, msg = analyze_password_strength(password)
        if not ok:
            raise ValueError(f"Weak password: {msg}")
        if username in self.users:
            raise ValueError("Username already exists.")
        pwd_hash = hash_password(password, pepper=self.pepper)
        secret = generate_totp_secret()
        self.users[username] = UserRecord(username, pwd_hash, secret, issuer=self.issuer)
        account = account_name_for_totp or username
        uri = otpauth_uri(secret, account, self.issuer, self.period, self.digits)
        return {"otpauth_uri": uri, "totp_secret": secret}

    def authenticate(self, username: str, password: str, totp_code: Optional[str] = None, require_totp: bool = False) -> bool:
        user = self.users.get(username)
        if not user:
            return False
        if not verify_password(password, user.password_hash, pepper=self.pepper):
            return False
        if require_totp:
            if not totp_code:
                return False
            if not verify_totp(user.totp_secret, totp_code, period=self.period, digits=self.digits, window=1):
                return False
        return True


# Demo run 
if __name__ == "__main__":
    auth = AuthSystem(issuer="NSSec Demo")
    username = "ana"
    password = "BetterPass!2025"

    reg = auth.register_user(username, password, account_name_for_totp="ana@example.com")
    print("User registered.")
    print("Provisioning URI:", reg["otpauth_uri"])
    print("TOTP secret:", reg["totp_secret"])

    print("Password-only auth:", auth.authenticate(username, password))
    code = totp_now(reg["totp_secret"])
    print("Current TOTP:", code)
    print("Password + TOTP auth:", auth.authenticate(username, password, totp_code=code, require_totp=True))
