import base64
import json
import re
import time
import hashlib
from io import BytesIO
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from typing import Optional, List, Dict
import time
import json
import base64
import hashlib
from pydantic import BaseModel
import nacl.signing
import nacl.exceptions

import cv2
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import nacl.exceptions
import nacl.signing
import numpy as np
from pydantic import BaseModel
import requests
import tldextract

# Dynamically locate the project root and frontend path
BASE_DIR = Path(__file__).resolve().parent.parent
INDEX_HTML_PATH = BASE_DIR / "frontend" / "index.html"

app = FastAPI(title="QR Security Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted issuer public keys
TRUSTED_ISSUERS = {
    "gate.corp.auth": "0paL0Z51OpWN6yzyqPQak0Tz66fdBu/0kOJ//R0Yo4s="
}

# Used Nonce Cache for Replay Attack Prevention (In-memory cache: nonce -> timestamp)
USED_NONCES: Dict[str, float] = {}

# Known Threat Intelligence Blacklist
KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}



class URLReport(BaseModel):
    original_url: str
    final_destination: str
    redirect_count: int
    is_homoglyph: bool
    domain: str
    risk_level: str
    notes: list[str]


class AuthCheckStep(BaseModel):
    name: str
    status: bool  # True = Pass, False = Fail
    detail: str

class SecurityReport(BaseModel):
    raw_payload: str
    payload_sha256: str
    is_blacklisted: bool
    authentication_verdict: str  # AUTHENTIC, REJECTED_TAMPERED, REJECTED_EXPIRED, REJECTED_REPLAY, UNSIGNED
    checks: List[AuthCheckStep]
    user_id: Optional[str] = "N/A"
    action: Optional[str] = "N/A"
    issuer: Optional[str] = "None (Unregistered)"
    target_url: Optional[str] = None
    url_analysis: Optional[URLReport] = None


def inspect_url(target_url: str) -> URLReport:
    """Follow redirects safely, inspect domain, and detect threats/spoofs."""
    parsed_url = urlparse(target_url)
    raw_hostname = (parsed_url.hostname or "").lower()

    # Check for trusted lab / internal enterprise domains
    is_trusted_internal = raw_hostname.endswith(".internal.corp") or raw_hostname in ["localhost", "127.0.0.1"]

    # 1. Homoglyph / Punycode Check (detects xn-- in raw hostname or non-ASCII unicode)
    is_homoglyph = "xn--" in raw_hostname or any(ord(char) > 127 for char in raw_hostname)

    parsed = tldextract.extract(target_url)
    domain_full = f"{parsed.subdomain}.{parsed.domain}.{parsed.suffix}".strip(".")

    notes = []
    suspicious_score = 0

    if is_homoglyph:
        notes.append("Punycode / Homoglyph detected: Character spoofing or lookalike domain.")
        suspicious_score += 3

    # 2. Check for direct IP addresses as hostnames (e.g. http://192.168.1.1/login)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw_hostname) and not is_trusted_internal:
        notes.append("Host is a raw IP address rather than a domain name.")
        suspicious_score += 2

    # 3. Phishing bait keywords in URL path or subdomain (ignored for trusted internal endpoints)
    if not is_trusted_internal:
        phish_keywords = ["phishing", "verify", "secure-login", "account-update", "signin", "banking"]
        found_keywords = [kw for kw in phish_keywords if kw in target_url.lower()]
        if found_keywords:
            notes.append(f"Suspicious security keywords detected: {', '.join(found_keywords)}")
            suspicious_score += 2

    # 4. Insecure HTTP check
    if parsed_url.scheme == "http":
        notes.append("Unencrypted HTTP protocol in use.")
        suspicious_score += 1

    # 5. Safe Redirect Resolution
    redirect_count = 0
    final_url = target_url

    # Bypass network probe for offline test/lab domains to avoid unreachable timeout penalties
    if is_trusted_internal:
        notes.append("Enterprise internal test domain recognized: live network probe bypassed.")
    else:
        try:
            session = requests.Session()
            session.max_redirects = 5
            res = session.head(
                target_url,
                allow_redirects=True,
                timeout=3.5,
                headers={"User-Agent": "QRSecurityGate/1.0 (AuditBot)"}
            )
            final_url = res.url
            redirect_count = len(res.history)
        except requests.TooManyRedirects:
            redirect_count = 5
            notes.append("Excessive redirect loop/cloaking detected (5+ hops).")
            suspicious_score += 3
        except requests.RequestException:
            notes.append("Target endpoint unreachable or connection timed out.")
            suspicious_score += 1

    if redirect_count >= 3:
        notes.append(f"Multi-hop redirect chain: {redirect_count} hops traversed.")
        suspicious_score += 2

    # 6. Compute Final Risk Level
    if suspicious_score >= 3 or is_homoglyph:
        risk = "HIGH"
    elif suspicious_score >= 1 or redirect_count > 1:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return URLReport(
        original_url=target_url,
        final_destination=final_url,
        redirect_count=redirect_count,
        is_homoglyph=is_homoglyph,
        domain=raw_hostname or domain_full,
        risk_level=risk,
        notes=notes
    )

def evaluate_payload(payload_str: str) -> SecurityReport:
    payload_sha256 = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    is_blacklisted = payload_sha256 in KNOWN_MALICIOUS_HASHES
    checks: List[AuthCheckStep] = []

    # Step 1: Structural Parsing
    data = None
    is_envelope = False
    try:
        data = json.loads(payload_str)
        if isinstance(data, dict) and "body" in data and "sig" in data and "payload_hash" in data:
            is_envelope = True
    except (json.JSONDecodeError, TypeError):
        pass

    if not is_envelope:
        url_rep = inspect_url(payload_str) if payload_str.startswith(("http://", "https://")) else None
        if is_blacklisted and url_rep:
            url_rep.risk_level = "HIGH"
            url_rep.notes.insert(0, "CRITICAL: SHA-256 matches threat database!")

        checks.append(AuthCheckStep(name="Payload Format", status=True, detail="Raw unencoded format detected"))
        checks.append(AuthCheckStep(name="Cryptographic Envelope", status=False, detail="No digital signature envelope found"))
        checks.append(AuthCheckStep(name="Authenticity Verification", status=False, detail="Skipped (Unsigned payload)"))

        return SecurityReport(
            raw_payload=payload_str,
            payload_sha256=payload_sha256,
            is_blacklisted=is_blacklisted,
            authentication_verdict="UNSIGNED",
            checks=checks,
            url_analysis=url_rep
        )

    # Extract Token Components
    body = data["body"]
    sig_b64 = data["sig"]
    claimed_hash = data["payload_hash"]

    user_id = body.get("user_id", "Unknown")
    action = body.get("action", "Unknown")
    target_url = body.get("u", "")
    issuer = body.get("iss", "Unknown")
    exp = body.get("exp", 0)
    nonce = body.get("nonce", "")

    # Reconstruct Canonical Payload
    canonical_str = f"{target_url}|{issuer}|{user_id}|{action}|{nonce}|{exp}"
    calculated_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    # Step 2: Hash Integrity Check
    hash_match = (calculated_hash == claimed_hash)
    checks.append(AuthCheckStep(
        name="SHA-256 Canonical Hash Match",
        status=hash_match,
        detail="Payload matches original digest" if hash_match else "Data altered after digest calculation"
    ))

    # Step 3: Issuer Identity & PKI Resolution
    issuer_trusted = issuer in TRUSTED_ISSUERS
    checks.append(AuthCheckStep(
        name="Trusted Issuer Authority",
        status=issuer_trusted,
        detail=f"Issued by verified authority: {issuer}" if issuer_trusted else f"Unknown or untrusted authority: {issuer}"
    ))

    # Step 4: Digital Signature Mathematical Verification (Ed25519)
    sig_valid = False
    if issuer_trusted:
        try:
            pubkey_bytes = base64.b64decode(TRUSTED_ISSUERS[issuer])
            verify_key = nacl.signing.VerifyKey(pubkey_bytes)
            verify_key.verify(canonical_str.encode("utf-8"), base64.b64decode(sig_b64))
            sig_valid = True
        except (nacl.exceptions.BadSignatureError, Exception):
            sig_valid = False

    checks.append(AuthCheckStep(
        name="Ed25519 Signature Verification",
        status=sig_valid,
        detail="Mathematical signature valid and authentic" if sig_valid else "Signature mismatch: Forged or modified claims"
    ))

    # Step 5: Freshness & Expiry Window Check
    is_expired = time.time() > exp
    checks.append(AuthCheckStep(
        name="Timestamp & Expiry Validation",
        status=not is_expired,
        detail=f"Token valid (Expires at epoch {exp})" if not is_expired else f"Token expired by {int(time.time() - exp)}s"
    ))

    # Step 6: Anti-Replay Nonce Check
    is_replayed = nonce in USED_NONCES
    if not is_replayed and not is_expired and sig_valid:
        USED_NONCES[nonce] = time.time()

    checks.append(AuthCheckStep(
        name="Anti-Replay Nonce Check",
        status=not is_replayed,
        detail="Single-use nonce verified" if not is_replayed else "Replay attack detected: Nonce already exhausted"
    ))

    # Final Authentication Verdict Resolution
    if not sig_valid or not hash_match:
        verdict = "REJECTED_TAMPERED"
    elif is_expired:
        verdict = "REJECTED_EXPIRED"
    elif is_replayed:
        verdict = "REJECTED_REPLAY"
    elif not issuer_trusted:
        verdict = "REJECTED_UNTRUSTED"
    else:
        verdict = "AUTHENTIC"

    url_rep = inspect_url(target_url) if target_url.startswith(("http://", "https://")) else None

    return SecurityReport(
        raw_payload=payload_str,
        payload_sha256=payload_sha256,
        is_blacklisted=is_blacklisted,
        authentication_verdict=verdict,
        checks=checks,
        user_id=user_id,
        action=action,
        issuer=issuer,
        target_url=target_url,
        url_analysis=url_rep
    )

@app.post("/api/scan/file", response_model=SecurityReport)
async def scan_file(file: UploadFile = File(...)):
    """Receives image upload, decodes QR matrix with OpenCV, and analyzes."""
    contents = await file.read()

    nparr = np.frombuffer(contents, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image file format.")

    detector = cv2.QRCodeDetector()
    raw_text, points, _ = detector.detectAndDecode(img)

    if not raw_text:
        raise HTTPException(status_code=422, detail="No QR code found in this image.")

    return evaluate_payload(raw_text)


class DirectTextRequest(BaseModel):
    payload: str


@app.post("/api/scan/text", response_model=SecurityReport)
async def scan_text(body: DirectTextRequest):
    """Directly evaluates a raw QR payload string."""
    return evaluate_payload(body.payload)


@app.get("/")
def serve_index():
    if not INDEX_HTML_PATH.exists():
        fallback_path = BASE_DIR / "index.html"
        if fallback_path.exists():
            return FileResponse(str(fallback_path))
        raise HTTPException(status_code=404, detail=f"Frontend template not found at {INDEX_HTML_PATH}")
    return FileResponse(str(INDEX_HTML_PATH))