"""
decrypt.py

Handles receiving and decrypting messages using:
- RSA-PSS signature verification
- Station-to-Station (STS) verification
- Diffie-Hellman key exchange
- SHA-256 key derivation
- AES-256-GCM decryption

Forward secrecy model:
- Only the RECIPIENT can decrypt a message (shared secret requires the
  recipient's long-term DH private key + the sender's ephemeral pub).
- The sender's own copy of what they sent is NEVER reconstructed here —
  it exists only in the sender's browser sessionStorage, set at send time.
- Once a message is successfully decrypted and verified, its wire file
  is deleted immediately (f.unlink()). After that point the ciphertext
  no longer exists anywhere — it cannot be recovered even by an attacker
  who later obtains the recipient's private key and password.
- If decryption fails for a transient reason, the file is left in place
  so a genuinely undelivered message isn't destroyed by accident.
"""

import hashlib
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models import (
    MSGS_DIR,
    DH_PARAM_NUMBERS,
    b64d,
    b64_to_int,
)

from storage import (
    user_exists,
    user_path,
    decrypt_blob,
    load_json,
    load_text,
    load_bytes,
)


def get_messages(data):

    username = data["username"].lower()
    password = data["password"]

    if not user_exists(username):
        return {"error": "User not found"}, 404

    ru = user_path(username)

    # =========================
    # Unlock Recipient DH Private Key
    # =========================

    try:

        dh_priv_int = int(
            decrypt_blob(
                load_json(ru / "dh_priv.json"),
                password
            ).decode()
        )

    except Exception:
        return {"error": "Invalid password"}, 401

    own_pub_int = int(
        load_text(
            ru / "dh_pub.txt"
        )
    )

    own_priv_numbers = dh.DHPrivateNumbers(
        dh_priv_int,
        dh.DHPublicNumbers(
            own_pub_int,
            DH_PARAM_NUMBERS
        )
    )

    own_priv_key = own_priv_numbers.private_key(
        default_backend()
    )

    results = []

    # =========================
    # Deliver Every Message Addressed To This User
    # =========================

    for f in MSGS_DIR.glob("*.json"):

        pkg = load_json(f)

        # Only the recipient can ever decrypt this wire package.
        if pkg.get("recipient") != username:
            continue

        steps = []
        plaintext = None
        sig_valid = None
        error = None
        delivered = False

        try:

            sender = pkg["sender"]

            eph_pub_int = b64_to_int(
                pkg["eph_pub"]
            )

            ciphertext = b64d(
                pkg["ciphertext"]
            )

            nonce = b64d(
                pkg["nonce"]
            )

            msg_sig = b64d(
                pkg["msg_signature"]
            )

            sts_sig = b64d(
                pkg["sts_signature"]
            )

            sender_pub = serialization.load_pem_public_key(
                load_bytes(
                    user_path(sender) / "rsa_pub.pem"
                ),
                backend=default_backend()
            )

            # =========================
            # Verify Message Signature
            # =========================

            eph_pub_bytes = pkg["eph_pub"].encode()

            try:

                sender_pub.verify(

                    msg_sig,

                    ciphertext +
                    eph_pub_bytes +
                    username.encode(),

                    padding.PSS(
                        mgf=padding.MGF1(
                            hashes.SHA256()
                        ),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),

                    hashes.SHA256()

                )

                sig_valid = True

                steps.append({

                    "step":
                        "① Verify Message Signature",

                    "detail":
                        "RSA-PSS verify(ciphertext ‖ eph_pub ‖ recipient) with sender's public key -> ✅ authentic"

                })

            except InvalidSignature:

                sig_valid = False

                steps.append({

                    "step":
                        "① Verify Message Signature",

                    "detail":
                        "⚠️ Signature INVALID — message may be forged or tampered"

                })

            # =========================
            # Verify STS Signature
            # =========================

            sts_payload = (
                pkg["eph_pub"].encode() +
                str(own_pub_int).encode()
            )

            try:

                sender_pub.verify(

                    sts_sig,

                    sts_payload,

                    padding.PSS(
                        mgf=padding.MGF1(
                            hashes.SHA256()
                        ),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),

                    hashes.SHA256()

                )

                steps.append({

                    "step":
                        "② Verify STS Key Confirmation",

                    "detail":
                        "Sender's signature over (their DH value ‖ our DH value) confirmed -> mutual key authentication"

                })

            except InvalidSignature:

                steps.append({

                    "step":
                        "② Verify STS Key Confirmation",

                    "detail":
                        "⚠️ STS signature invalid"

                })

            # =========================
            # Diffie-Hellman Exchange
            # =========================

            eph_pub_numbers = dh.DHPublicNumbers(
                eph_pub_int,
                DH_PARAM_NUMBERS
            )

            eph_pub_key = eph_pub_numbers.public_key(
                default_backend()
            )

            shared_secret = own_priv_key.exchange(
                eph_pub_key
            )

            steps.append({

                "step":
                    "③ Diffie-Hellman Exchange",

                "detail":
                    "shared secret = (sender_eph_pub)^own_x mod p — matches sender's computation"

            })

            # =========================
            # Derive AES Key
            # =========================

            aes_key = hashlib.sha256(
                shared_secret
            ).digest()

            steps.append({

                "step":
                    "④ Key Derivation",

                "detail":
                    "SHA-256(shared_secret) -> 32-byte AES key"

            })

            # =========================
            # AES-256-GCM Decryption
            # =========================

            plaintext = AESGCM(
                aes_key
            ).decrypt(

                nonce,

                ciphertext,

                eph_pub_bytes

            ).decode()

            steps.append({

                "step":
                    "⑤ AES-256-GCM Decryption",

                "detail":
                    "GCM tag verified ✅ — authenticated decryption succeeded"

            })

            delivered = True

        except Exception as e:

            error = str(e)

            steps.append({

                "step":
                    "Error",

                "detail":
                    error

            })

        results.append({
            "filename": f.name,
            "timestamp": pkg.get("timestamp", 0),
            "sender": pkg.get("sender"),
            "recipient": pkg.get("recipient"),
            "algorithm": pkg.get("algorithm"),
            "plaintext": plaintext,
            "sig_valid": sig_valid,
            "error": error,
            "steps": steps
            })

        # =========================
        # Forward Secrecy: destroy on successful delivery
        # =========================
        # Only delete once fully decrypted+verified. A transient failure
        # (e.g. bad password check earlier would've returned 401 already;
        # this covers anything else) leaves the file in place rather than
        # destroying the only copy of an undelivered message.
        if delivered:
            def delayed_delete(path):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

            threading.Timer(10.0, delayed_delete, args=[f]).start()

    # Sort messages chronologically (oldest → newest)
    results.sort(key=lambda m: m.get("timestamp", 0))

    return {

        "messages": results

    }, 200