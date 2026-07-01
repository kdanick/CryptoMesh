"""
encrypt.py

Handles sending encrypted messages using:
- Diffie-Hellman
- Station-to-Station (STS)
- RSA-PSS
- AES-256-GCM
"""

import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from models import (
    DH_PARAMETERS,
    DH_PARAM_NUMBERS,
    MSGS_DIR,
    b64e,
    int_to_b64,
)

from storage import (
    user_exists,
    user_path,
    decrypt_blob,
    load_json,
    load_text,
    load_bytes,
    save_json,
)


def send_message(data):

    sender = data["sender"].lower()
    recipient = data["recipient"].lower()
    message = data["message"]
    password = data["password"]

    if not user_exists(sender) or not user_exists(recipient):
        return {"error": "Sender or recipient not found"}, 404

    su = user_path(sender)
    ru = user_path(recipient)

    # =========================
    # Unlock sender RSA private key
    # =========================

    try:
        rsa_priv_pem = decrypt_blob(
            load_json(su / "rsa_priv.json"),
            password
        )
    except Exception:
        return {"error": "Invalid password"}, 401

    rsa_priv = serialization.load_pem_private_key(
        rsa_priv_pem,
        password=None,
        backend=default_backend()
    )

    # =========================
    # Generate Ephemeral DH Key Pair
    # =========================

    eph_priv = DH_PARAMETERS.generate_private_key()

    eph_pub_int = eph_priv.public_key().public_numbers().y

    recip_dh_pub_int = int(
        load_text(
            ru / "dh_pub.txt"
        )
    )

    recip_pub_numbers = dh.DHPublicNumbers(
        recip_dh_pub_int,
        DH_PARAM_NUMBERS
    )

    recip_pub_key = recip_pub_numbers.public_key(
        default_backend()
    )

    shared_secret = eph_priv.exchange(
        recip_pub_key
    )

    # =========================
    # Station-to-Station Signature
    # =========================

    sts_payload = (
        int_to_b64(eph_pub_int).encode()
        + str(recip_dh_pub_int).encode()
    )

    sts_signature = rsa_priv.sign(
        sts_payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # =========================
    # Derive AES Key
    # =========================

    aes_key = hashlib.sha256(
        shared_secret
    ).digest()

    # =========================
    # AES-256-GCM Encryption
    # =========================

    import os

    nonce = os.urandom(12)

    eph_pub_bytes = int_to_b64(
        eph_pub_int
    ).encode()

    ciphertext = AESGCM(
        aes_key
    ).encrypt(
        nonce,
        message.encode(),
        eph_pub_bytes
    )

    # =========================
    # Message Signature
    # =========================

    msg_signature = rsa_priv.sign(
        ciphertext +
        eph_pub_bytes +
        recipient.encode(),

        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),

        hashes.SHA256()
    )

    # =========================
    # Package Message
    # =========================

    pkg = {

    "sender": sender,
    "recipient": recipient,

    # Sender's local copy
    "sender_plaintext": message,

    "eph_pub": int_to_b64(eph_pub_int),

    "ciphertext": b64e(ciphertext),

    "nonce": b64e(nonce),

    "sts_signature": b64e(sts_signature),

    "msg_signature": b64e(msg_signature),
    
    "timestamp": time.time(),

    "algorithm":
        "DH (2048-bit MODP) + STS + RSA-2048 + AES-256-GCM"
}
    idx = len(
        list(
            MSGS_DIR.glob("*.json")
        )
    )

    filename = (
        f"msg_{sender}_to_{recipient}_{idx}.json"
    )

    save_json(
        MSGS_DIR / filename,
        pkg
    )

    return {

        "success": True,

        "steps": [

            {
                "step": "① Unlock Signing Key",
                "detail":
                    "SHA-256(salt ‖ password) -> KEK -> AES-GCM decrypt sender's RSA private key"
            },

            {
                "step": "② Diffie-Hellman Exchange",
                "detail":
                    f"Ephemeral y = g^x mod p -> {hex(eph_pub_int)[:30]}… ; shared secret computed as (recipient_pub)^x mod p"
            },

            {
                "step": "③ Station-to-Station Signature",
                "detail":
                    "RSA-PSS signs (own DH value ‖ peer DH value) -> binds identity to this exact exchange (key confirmation, prevents replay/MITM)"
            },

            {
                "step": "④ Key Derivation",
                "detail":
                    "SHA-256(shared_secret) -> 32-byte AES key"
            },

            {
                "step": "⑤ AES-256-GCM Encryption",
                "detail":
                    f"nonce={b64e(nonce)[:16]}…  ciphertext={b64e(ciphertext)[:28]}…"
            },

            {
                "step": "⑥ Message Signature",
                "detail":
                    "RSA-PSS signs (ciphertext ‖ eph_pub ‖ recipient) for sender authentication"
            },

            {
                "step": "⑦ Saved to disk",
                "detail":
                    f"File: {filename}"
            }

        ]

    }, 200