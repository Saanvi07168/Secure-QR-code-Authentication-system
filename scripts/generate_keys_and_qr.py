import base64
import json
import time
import nacl.signing
import qrcode

# 1. Generate an Ed25519 keypair
signing_key = nacl.signing.SigningKey.generate()
verify_key = signing_key.verify_key

pubkey_b64 = base64.b64encode(verify_key.encode()).decode("utf-8")
print("=====================================================")
print(f"COPY THIS PUBLIC KEY INTO app.py TRUSTED_ISSUERS:")
print(f"'{pubkey_b64}'")
print("=====================================================\n")

issuer = "corp.payments"
exp = int(time.time()) + 86400  # Valid for 24 hours

# --- 1. Generate Valid Signed QR ---
valid_url = "https://httpbin.org/status/200"
msg_valid = f"{valid_url}|{issuer}|{exp}".encode("utf-8")
sig_valid = base64.b64encode(signing_key.sign(msg_valid).signature).decode("utf-8")

payload_valid = json.dumps({
    "u": valid_url,
    "iss": issuer,
    "exp": exp,
    "sig": sig_valid
}, separators=(',', ':'))

qr1 = qrcode.make(payload_valid)
qr1.save("valid_qr.png")
print("[+] Generated: valid_qr.png (Authentic)")

# --- 2. Generate Tampered QR (Attacker swapped the URL post-signing) ---
tampered_url = "https://httpbin.org/redirect/3"
payload_tampered = json.dumps({
    "u": tampered_url,  # URL altered, signature remains original
    "iss": issuer,
    "exp": exp,
    "sig": sig_valid
}, separators=(',', ':'))

qr2 = qrcode.make(payload_tampered)
qr2.save("tampered_qr.png")
print("[+] Generated: tampered_qr.png (Tampered URL mismatch)")

# --- 3. Generate Plain Unsigned QR ---
qr3 = qrcode.make("https://httpbin.org/redirect/2")
qr3.save("unsigned_qr.png")
print("[+] Generated: unsigned_qr.png (Standard unsigned URL)")