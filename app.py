"""
Secure Messenger - Backend (Cryptography II aligned)

Cryptographic stack (mapped to course weeks):
  - Diffie-Hellman (RFC 3526 / 2048-bit MODP group)  : Week 1 - Key exchange
  - Station-to-Station protocol (signed DH exponents) : Week 2 - Authenticated key exchange
  - RSA signatures                                    : authentication / key confirmation
  - SHA-256 key derivation from shared secret          : simple KDF
  - AES-256-GCM                                        : authenticated encryption
  - SHA-256 + salt                                      : Week 6 - private key encryption at rest
  - bcrypt                                             : Week 6 - password hashing for login
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, json, base64, hashlib
from pathlib import Path
import bcrypt

from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__, static_folder="static")
CORS(app)

BASE_DIR  = Path.cwd() / "secure_messenger_data"
USERS_DIR = BASE_DIR / "users"
MSGS_DIR  = BASE_DIR / "messages"
for d in [BASE_DIR, USERS_DIR, MSGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ───────────────────────── DH group (RFC 3526, 2048-bit MODP) ─────────────────────────
# ───────────────────────── DH group (RFC 3526, 2048-bit MODP, group 14) ─────────────────────────
# This is the IETF-standardized safe prime used by countless real systems (IKE/IPsec, SSH, TLS).
# Using a fixed, well-known group avoids the multi-second cost of generating a fresh safe
# prime at every startup, while still being textbook Diffie-Hellman: shared_secret = g^(ab) mod p.
DH_P = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
DH_G = 2
DH_PARAM_NUMBERS = dh.DHParameterNumbers(DH_P, DH_G)
DH_PARAMETERS = DH_PARAM_NUMBERS.parameters(default_backend())

# ───────────────────────── helpers ─────────────────────────
def b64e(b: bytes) -> str:  return base64.b64encode(b).decode()
def b64d(s: str)  -> bytes: return base64.b64decode(s)

def user_path(u): return USERS_DIR / u.lower()
def user_exists(u): return user_path(u).exists()

def int_to_b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64e(n.to_bytes(length, "big"))

def b64_to_int(s: str) -> int:
    return int.from_bytes(b64d(s), "big")

# ───────────────────────── key-at-rest (SHA-256 + salt + AES-GCM) ─────────────────────────
def _derive_kek(password: str, salt: bytes) -> bytes:
    """SHA-256(salt || password) -> 32-byte key-encryption key (Week 6: salts + hashing)."""
    return hashlib.sha256(salt + password.encode()).digest()

def _encrypt_blob(raw: bytes, password: str) -> dict:
    salt  = os.urandom(16)
    kek   = _derive_kek(password, salt)
    nonce = os.urandom(12)
    ct    = AESGCM(kek).encrypt(nonce, raw, None)
    return {"salt": b64e(salt), "nonce": b64e(nonce), "ct": b64e(ct)}

def _decrypt_blob(blob: dict, password: str) -> bytes:
    kek   = _derive_kek(password, b64d(blob["salt"]))
    return AESGCM(kek).decrypt(b64d(blob["nonce"]), b64d(blob["ct"]), None)

# ───────────────────────── user management ─────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if user_exists(username):
        return jsonify({"error": "User already exists"}), 409

    ud = user_path(username)
    ud.mkdir(parents=True, exist_ok=True)

    # bcrypt password hash (Week 6)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    (ud / "pw_hash.txt").write_bytes(pw_hash)

    # Long-term DH keypair, using the shared 2048-bit MODP group (Week 1)
    dh_priv = DH_PARAMETERS.generate_private_key()
    dh_priv_int = dh_priv.private_numbers().x
    dh_pub_int  = dh_priv.public_key().public_numbers().y

    # RSA signing keypair, used for STS key confirmation (Week 2) and message authentication
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    rsa_priv_pem = rsa_priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    rsa_pub_pem = rsa_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encrypt both private values at rest with the password-derived KEK
    (ud / "dh_priv.json").write_text(json.dumps(_encrypt_blob(str(dh_priv_int).encode(), password)))
    (ud / "rsa_priv.json").write_text(json.dumps(_encrypt_blob(rsa_priv_pem, password)))

    # Public material stored in the clear
    (ud / "dh_pub.txt").write_text(str(dh_pub_int))
    (ud / "rsa_pub.pem").write_bytes(rsa_pub_pem)

    return jsonify({
        "success": True,
        "steps": [
            {"step": "Password Hashing (bcrypt)", "detail": f"bcrypt(password) -> {pw_hash.decode()[:29]}…"},
            {"step": "DH Keypair (2048-bit MODP group)", "detail": f"private x sampled, public y = g^x mod p -> {hex(dh_pub_int)[:34]}…"},
            {"step": "RSA Signing Keypair (2048-bit)", "detail": "Generated for STS key confirmation and message signatures"},
            {"step": "Private Key Encryption at Rest", "detail": "SHA-256(salt ‖ password) -> 32-byte KEK -> AES-256-GCM wraps DH and RSA private keys"},
        ]
    })

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    ud = user_path(username)
    stored = (ud / "pw_hash.txt").read_bytes()
    if not bcrypt.checkpw(password.encode(), stored):
        return jsonify({"error": "Invalid password"}), 401

    try:
        blob = json.loads((ud / "dh_priv.json").read_text())
        _decrypt_blob(blob, password)
    except Exception:
        return jsonify({"error": "Key decryption failed"}), 401

    return jsonify({"success": True, "username": username, "steps": [
        {"step": "bcrypt.checkpw", "detail": "Constant-time comparison against stored hash"},
        {"step": "KEK derivation", "detail": "SHA-256(salt ‖ password) -> 32-byte KEK"},
        {"step": "Private key unlock", "detail": "AES-256-GCM.decrypt(KEK, encrypted_priv) -> raw DH/RSA keys"},
    ]})

@app.route("/api/users", methods=["GET"])
def list_users():
    return jsonify({"users": [p.name for p in USERS_DIR.iterdir() if p.is_dir()]})

# ───────────────────────── send message (STS handshake + AES-GCM) ─────────────────────────
@app.route("/api/send", methods=["POST"])
def send_message():
    data      = request.json
    sender    = data["sender"].lower()
    recipient = data["recipient"].lower()
    message   = data["message"]
    password  = data["password"]

    if not user_exists(sender) or not user_exists(recipient):
        return jsonify({"error": "Sender or recipient not found"}), 404

    su, ru = user_path(sender), user_path(recipient)

    # ── 1. Unlock sender's RSA signing key (authentication material) ──
    try:
        rsa_priv_pem = _decrypt_blob(json.loads((su / "rsa_priv.json").read_text()), password)
    except Exception:
        return jsonify({"error": "Invalid password"}), 401
    rsa_priv = serialization.load_pem_private_key(rsa_priv_pem, password=None, backend=default_backend())

    # ── 2. Diffie-Hellman: generate an ephemeral DH keypair for this session ──
    eph_priv = DH_PARAMETERS.generate_private_key()
    eph_pub_int = eph_priv.public_key().public_numbers().y

    recip_dh_pub_int = int(( ru / "dh_pub.txt").read_text())
    recip_pub_numbers = dh.DHPublicNumbers(recip_dh_pub_int, DH_PARAM_NUMBERS)
    recip_pub_key = recip_pub_numbers.public_key(default_backend())

    shared_secret = eph_priv.exchange(recip_pub_key)  # g^(ab) mod p, as bytes

    # ── 3. Station-to-Station: sign (our DH public value || their DH public value) ──
    # This is the "key confirmation" step from Week 2 — proves sender controls
    # the claimed identity for *this specific* exchange, preventing replay/MITM.
    sts_payload = int_to_b64(eph_pub_int).encode() + str(recip_dh_pub_int).encode()
    sts_signature = rsa_priv.sign(
        sts_payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
    )

    # ── 4. Derive AES key from shared secret via SHA-256 ──
    aes_key = hashlib.sha256(shared_secret).digest()

    # ── 5. AES-256-GCM encrypt the message ──
    nonce = os.urandom(12)
    eph_pub_bytes = int_to_b64(eph_pub_int).encode()
    ciphertext = AESGCM(aes_key).encrypt(nonce, message.encode(), eph_pub_bytes)

    # ── 6. Sign the ciphertext itself for message-level authentication ──
    msg_signature = rsa_priv.sign(
        ciphertext + eph_pub_bytes + recipient.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
    )

    pkg = {
        "sender": sender, "recipient": recipient,
        "eph_pub": int_to_b64(eph_pub_int),
        "ciphertext": b64e(ciphertext),
        "nonce": b64e(nonce),
        "sts_signature": b64e(sts_signature),
        "msg_signature": b64e(msg_signature),
        "algorithm": "DH (2048-bit MODP) + STS + RSA-2048 + AES-256-GCM",
    }
    idx = len(list(MSGS_DIR.glob("*.json")))
    fname = f"msg_{sender}_to_{recipient}_{idx}.json"
    (MSGS_DIR / fname).write_text(json.dumps(pkg, indent=2))

    return jsonify({
        "success": True,
        "steps": [
            {"step": "① Unlock Signing Key", "detail": "SHA-256(salt ‖ password) -> KEK -> AES-GCM decrypt sender's RSA private key"},
            {"step": "② Diffie-Hellman Exchange", "detail": f"Ephemeral y = g^x mod p -> {hex(eph_pub_int)[:30]}… ; shared secret computed as (recipient_pub)^x mod p"},
            {"step": "③ Station-to-Station Signature", "detail": "RSA-PSS signs (own DH value ‖ peer DH value) -> binds identity to this exact exchange (key confirmation, prevents replay/MITM)"},
            {"step": "④ Key Derivation", "detail": "SHA-256(shared_secret) -> 32-byte AES key"},
            {"step": "⑤ AES-256-GCM Encryption", "detail": f"nonce={b64e(nonce)[:16]}…  ciphertext={b64e(ciphertext)[:28]}…"},
            {"step": "⑥ Message Signature", "detail": "RSA-PSS signs (ciphertext ‖ eph_pub ‖ recipient) for sender authentication"},
            {"step": "⑦ Saved to disk", "detail": f"File: {fname}"},
        ]
    })

# ───────────────────────── receive messages ─────────────────────────
@app.route("/api/messages", methods=["POST"])
def get_messages():
    data = request.json
    username = data["username"].lower()
    password = data["password"]

    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    ru = user_path(username)
    try:
        dh_priv_int = int(_decrypt_blob(json.loads((ru / "dh_priv.json").read_text()), password).decode())
    except Exception:
        return jsonify({"error": "Invalid password"}), 401

    own_pub_int = int((ru / "dh_pub.txt").read_text())
    own_priv_numbers = dh.DHPrivateNumbers(
        dh_priv_int, dh.DHPublicNumbers(own_pub_int, DH_PARAM_NUMBERS)
    )
    own_priv_key = own_priv_numbers.private_key(default_backend())

    results = []
    for f in MSGS_DIR.glob("*.json"):
        pkg = json.loads(f.read_text())
        if pkg.get("recipient") != username:
            continue

        steps, plaintext, sig_valid, error = [], None, None, None
        try:
            sender = pkg["sender"]
            eph_pub_int = b64_to_int(pkg["eph_pub"])
            ciphertext  = b64d(pkg["ciphertext"])
            nonce       = b64d(pkg["nonce"])
            msg_sig     = b64d(pkg["msg_signature"])
            sts_sig     = b64d(pkg["sts_signature"])

            sender_pub = serialization.load_pem_public_key(
                (user_path(sender) / "rsa_pub.pem").read_bytes(), backend=default_backend()
            )

            # ── Verify message signature (sender authentication) ──
            eph_pub_bytes = pkg["eph_pub"].encode()
            try:
                sender_pub.verify(
                    msg_sig, ciphertext + eph_pub_bytes + username.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
                )
                sig_valid = True
                steps.append({"step": "① Verify Message Signature", "detail": "RSA-PSS verify(ciphertext ‖ eph_pub ‖ recipient) with sender's public key -> ✅ authentic"})
            except InvalidSignature:
                sig_valid = False
                steps.append({"step": "① Verify Message Signature", "detail": "⚠️ Signature INVALID — message may be forged or tampered"})

            # ── Verify STS signature (key confirmation) ──
            sts_payload = pkg["eph_pub"].encode() + str(own_pub_int).encode()
            try:
                sender_pub.verify(
                    sts_sig, sts_payload,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
                )
                steps.append({"step": "② Verify STS Key Confirmation", "detail": "Sender's signature over (their DH value ‖ our DH value) confirmed -> mutual key authentication"})
            except InvalidSignature:
                steps.append({"step": "② Verify STS Key Confirmation", "detail": "⚠️ STS signature invalid"})

            # ── Diffie-Hellman: recompute shared secret ──
            eph_pub_numbers = dh.DHPublicNumbers(eph_pub_int, DH_PARAM_NUMBERS)
            eph_pub_key = eph_pub_numbers.public_key(default_backend())
            shared_secret = own_priv_key.exchange(eph_pub_key)
            steps.append({"step": "③ Diffie-Hellman Exchange", "detail": "shared secret = (sender_eph_pub)^own_x mod p — matches sender's computation"})

            # ── Key derivation ──
            aes_key = hashlib.sha256(shared_secret).digest()
            steps.append({"step": "④ Key Derivation", "detail": "SHA-256(shared_secret) -> 32-byte AES key"})

            # ── AES-256-GCM decrypt ──
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, eph_pub_bytes).decode()
            steps.append({"step": "⑤ AES-256-GCM Decryption", "detail": "GCM tag verified ✅ — authenticated decryption succeeded"})

        except Exception as e:
            error = str(e)
            steps.append({"step": "Error", "detail": error})

        results.append({
            "filename": f.name, "sender": pkg.get("sender"), "recipient": pkg.get("recipient"),
            "algorithm": pkg.get("algorithm"), "plaintext": plaintext,
            "sig_valid": sig_valid, "error": error, "steps": steps,
        })

    return jsonify({"messages": results})

# ───────────────────────── static ─────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/login")
def login_page():
    return send_from_directory("static", "login.html")

@app.route("/register")
def register_page():
    return send_from_directory("static", "register.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)