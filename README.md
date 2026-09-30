# Secure-QR-code-Authentication-system

An enterprise-grade cybersecurity gateway and threat detonation engine designed to mitigate QR code-based attacks (Quishing, unauthorized URL redirection, replay attacks, and payload tampering). 

The platform employs a dual-layer security architecture combining an **Ed25519 Cryptographic Envelope Pipeline** with an active **Heuristic URL Detonation Engine**.

---

## 🌟 Key Features

### 1. Dual-Layer Zero-Trust Architecture
**Cryptographic Layer (Public Key Infrastructure):**
**Ed25519 (256-bit elliptic-curve cryptography):** Validates digital signatures to guarantee origin authenticity and non-repudiation.
**SHA-256 Canonical Digest Matching:** Calculates cryptographic hashes over structured canonical payloads to instantly detect bit-level data tampering.
  * **Replay Protection (Single-Use Nonces):** Employs cryptographically secure pseudo-random nonces to neutralize token replay attacks.
  * **Ephemeral TTL Enforcement:** Rejects expired tokens based on embedded UNIX timestamps.
* **Network Detonation & Heuristic Inspection Layer:**
  * **Redirect Tracing:** Unwinds obfuscated URL hops safely using automated HTTP session tracing.
  * **Spoofing & Homoglyph Detection:** Flags Punycode/IDN homograph attacks (`xn--`) and deceptive IP-based hosts.
  * **Threat Intelligence Blacklist:** Compares payload fingerprints against known malicious SHA-256 digests.
  * **Default-Deny Policy:** Unauthenticated standard QR codes are safely isolated, falling back to pure heuristic analysis without granting privileged access.
    
## 🛠️ Tech Stack

**Backend:** Python 3, FastAPI, Uvicorn, Pydantic
**Cryptography:** PyNaCl (`libsodium` Ed25519), Python `hashlib` (SHA-256), `secrets`
**Inspection & Detonation:** Requests, `tldextract`, `urllib.parse`
**Frontend:** Vanilla JavaScript (ES6+), HTML5, Tailwind CSS
**Testing & Artifacts:** `qrcode`, Pillow (PIL)

## 📁 Project Structure

```text
├── backend/
│   ├── app.py                # FastAPI endpoints, threat intelligence & verification routing
│   ├── crypto_engine.py      # Ed25519 signature checks, SHA-256 canonical hashing & nonce auditing
│   └── detonation_engine.py  # Redirect tracing, homoglyph detection & heuristic scoring
├── frontend/
│   ├── index.html            # Dark-mode dashboard (1/3 Identity, 2/3 Analysis grid)
│   └── script.js             # Client-side scan ingestion, telemetry binding & verdict rendering
├── scripts/
│   └── generate_auth_qrs.py  # Synthesizes test vectors (valid, tampered, expired, replay, unsigned)
├── test_samples/             # Generated test QR image artifacts
├── requirements.txt          # Python dependencies
└── README.md
