import os
import time
import json
import base64
import hashlib
import secrets
import qrcode
import nacl.signing
import nacl.encoding

# 1. Deterministic Corporate Signing Keypair for the Demo
seed = hashlib.sha256(b"university-secure-gateway-root-key").digest()
signing_key = nacl.signing.SigningKey(seed)
verify_key = signing_key.verify_key

pubkey_b64 = base64.b64encode(verify_key.encode()).decode("utf-8")
print(f"[*] Gateway Trusted Public Key (Base64):\n{pubkey_b64}\n")

os.makedirs("test_samples", exist_ok=True)

def build_signed_qr(user_id: str, action: str, target_url: str, ttl_seconds: int = 300, tamper: bool = False, unsigned: bool = False):
    now = int(time.time())
    exp = now + ttl_seconds
    nonce = secrets.token_hex(8)

    # Core claims
    payload_body = {
        "user_id": user_id,
        "action": action,
        "u": target_url,
        "exp": exp,
        "nonce": nonce,
        "iss": "gate.corp.auth"
    }

    # 1. Canonical String Representation for consistent hashing & signing
    canonical_str = f"{payload_body['u']}|{payload_body['iss']}|{payload_body['user_id']}|{payload_body['action']}|{payload_body['nonce']}|{payload_body['exp']}"
    
    # 2. SHA-256 Digest of canonical payload
    payload_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    if unsigned:
        return json.dumps({"u": target_url, "user_id": user_id, "note": "Unsigned pass"})

    # 3. Ed25519 Digital Signature over canonical payload
    signed_bytes = signing_key.sign(canonical_str.encode("utf-8")).signature
    sig_b64 = base64.b64encode(signed_bytes).decode("utf-8")

    # Intentional Tampering: alter URL after signature is stamped
    if tamper:
        payload_body["u"] = "http://phishing-attacker.evil/steal-session"

    envelope = {
        "body": payload_body,
        "payload_hash": payload_hash,
        "sig": sig_b64
    }
    return json.dumps(envelope)

def save_qr(filename: str, raw_text: str):
    qr = qrcode.QRCode(box_size=8, border=3)
    qr.add_data(raw_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    path = os.path.join("test_samples", filename)
    img.save(path)
    print(f"Generated: {path}")

# --- Generate the 5 Demo Test Cases ---
save_qr("1_valid_auth.png", build_signed_qr("EMP-9402", "GATE_ACCESS", "https://portal.internal.corp/verify"))
save_qr("2_tampered_payload.png", build_signed_qr("EMP-9402", "ADMIN_OVERRIDE", "https://portal.internal.corp/admin", tamper=True))
save_qr("3_expired_token.png", build_signed_qr("EMP-8104", "GATE_ACCESS", "https://portal.internal.corp/verify", ttl_seconds=-600))
save_qr("4_unsigned_qr.png", build_signed_qr("EMP-1100", "VISITOR", "https://guest-wifi.internal.corp", unsigned=True))

malicious_payload = "http://suspicious-bank-login.xyz/login?account=fake"
save_qr("5_malicious_threat.png", malicious_payload)

print("\n[✓] All 5 cryptographic test cases created in ./test_samples/")