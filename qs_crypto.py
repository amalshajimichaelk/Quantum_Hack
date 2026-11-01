"""QuantumShield core cryptography (hackathon prototype, NOT audited).

Primitives (nothing is hand-rolled):
  X25519, HKDF-SHA256, AES-256-GCM, scrypt -> `cryptography` (OpenSSL)
  ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) -> `pqcrypto` (PQClean C code)

Container format (messages and files):
  b"QSH1" | uint32 header_len | header JSON | AES-256-GCM ciphertext+tag
  The magic + length + header are the AES-GCM associated data, so changing the
  mode label, nonce, KEM ciphertext or filename is detected.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pqcrypto.kem import ml_kem_768 as _kem
from pqcrypto.sign import ml_dsa_65 as _dsa

MODES = ("classical", "pqc", "hybrid")
MODE_LABEL = {
    "classical": "X25519 + HKDF-SHA256 + AES-256-GCM",
    "pqc": "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM",
    "hybrid": "X25519 || ML-KEM-768 + HKDF-SHA256 + AES-256-GCM",
}
MAGIC = b"QSH1"
_SALT = b"QuantumShield/v1/salt"
# Header fields each mode requires. A missing field is an error, never a downgrade.
_FIELDS = {
    "classical": ("x25519_eph",),
    "pqc": ("mlkem_ct",),
    "hybrid": ("x25519_eph", "mlkem_ct"),
}
SIZES = {
    "x25519_pk": 32,
    "mlkem_pk": _kem.PUBLIC_KEY_SIZE,
    "mlkem_ct": _kem.CIPHERTEXT_SIZE,
    "mldsa_pk": _dsa.PUBLIC_KEY_SIZE,
    "mldsa_sig": _dsa.SIGNATURE_SIZE,
}


class QSError(Exception):
    """Base class for QuantumShield errors."""


class IntegrityError(QSError):
    """Ciphertext/header was modified, corrupted, or the wrong key was used."""


class ModeMismatchError(QSError):
    """Container mode differs from the mode the caller required."""


class MissingKeyError(QSError):
    """A key required by the selected mode is absent (no silent fallback)."""


# --------------------------------------------------------------------------- keys
@dataclass
class PublicBundle:
    x_pub: bytes
    kem_pk: bytes
    dsa_pk: bytes


@dataclass
class Identity:
    """Long-term keys. Private parts are excluded from repr and never displayed."""

    name: str
    x_pub: bytes
    kem_pk: bytes
    dsa_pk: bytes
    x_sk: X25519PrivateKey = field(repr=False)
    kem_sk: bytes = field(repr=False)
    dsa_sk: bytes = field(repr=False)

    def public(self) -> PublicBundle:
        return PublicBundle(self.x_pub, self.kem_pk, self.dsa_pk)

    def fingerprint(self) -> str:
        h = hashlib.sha256(self.x_pub + self.kem_pk + self.dsa_pk).hexdigest()
        return ":".join(h[i : i + 4] for i in range(0, 24, 4))


def x25519_keygen() -> tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def generate_identity(name: str = "Recipient") -> Identity:
    x_sk, x_pub = x25519_keygen()
    kem_pk, kem_sk = _kem.keygen()
    dsa_pk, dsa_sk = _dsa.keygen()
    return Identity(name, x_pub, kem_pk, dsa_pk, x_sk, kem_sk, dsa_sk)


# ----------------------------------------------------------------- key derivation
def _lp(*parts: bytes) -> bytes:
    """Length-prefixed concatenation (unambiguous encoding for KDF context)."""
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def _kdf(mode: str, secrets: list[bytes], ctx: bytes) -> bytes:
    """HKDF-SHA256 -> 32-byte AES key. Hybrid feeds BOTH secrets (ML-KEM || X25519)
    into one extract step, and binds mode + public values into `info`."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        info=b"QuantumShield/v1/aes256gcm/" + mode.encode() + b"\x00" + ctx,
    ).derive(b"".join(secrets))


def _ctx(mode, x_pub, eph, kem_pk, kem_ct) -> bytes:
    uses_x = mode in ("classical", "hybrid")
    uses_k = mode in ("pqc", "hybrid")
    return _lp(
        x_pub if uses_x else b"",
        eph if uses_x else b"",
        kem_pk if uses_k else b"",
        kem_ct if uses_k else b"",
    )


def establish(mode: str, pub: PublicBundle) -> tuple[bytes, dict[str, bytes]]:
    """Sender side: returns (aes_key, header_fields). Raises if a needed key is missing."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}")
    secrets: list[bytes] = []
    fields: dict[str, bytes] = {}
    eph = kem_ct = b""
    if mode in ("pqc", "hybrid"):
        if not pub.kem_pk:
            raise MissingKeyError(f"{mode} mode requires an ML-KEM-768 public key")
        kem_ct, ss_k = _kem.encaps(pub.kem_pk)
        secrets.append(ss_k)
        fields["mlkem_ct"] = kem_ct
    if mode in ("classical", "hybrid"):
        if not pub.x_pub:
            raise MissingKeyError(f"{mode} mode requires an X25519 public key")
        e_sk, eph = x25519_keygen()
        secrets.append(e_sk.exchange(X25519PublicKey.from_public_bytes(pub.x_pub)))
        fields["x25519_eph"] = eph
    key = _kdf(mode, secrets, _ctx(mode, pub.x_pub, eph, pub.kem_pk, kem_ct))
    return key, fields


def recover(mode: str, ident: Identity, fields: dict[str, bytes]) -> bytes:
    """Recipient side: re-derive the AES key from header fields."""
    secrets: list[bytes] = []
    eph = fields.get("x25519_eph", b"")
    kem_ct = fields.get("mlkem_ct", b"")
    try:
        if mode in ("pqc", "hybrid"):
            secrets.append(_kem.decaps(ident.kem_sk, kem_ct))
        if mode in ("classical", "hybrid"):
            secrets.append(ident.x_sk.exchange(X25519PublicKey.from_public_bytes(eph)))
    except ValueError as exc:
        raise IntegrityError("Invalid key-establishment data in header") from exc
    return _kdf(mode, secrets, _ctx(mode, ident.x_pub, eph, ident.kem_pk, kem_ct))


# ------------------------------------------------------------------- container
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def encrypt(mode: str, pub: PublicBundle, plaintext: bytes, filename: str = "") -> bytes:
    key, fields = establish(mode, pub)
    nonce = os.urandom(12)
    hdr = {
        "v": 1,
        "mode": mode,
        "alg": MODE_LABEL[mode],
        "nonce": _b64(nonce),
        "filename": filename,
        **{k: _b64(v) for k, v in fields.items()},
    }
    hdr_b = json.dumps(hdr, sort_keys=True, separators=(",", ":")).encode()
    aad = MAGIC + struct.pack(">I", len(hdr_b)) + hdr_b
    return aad + AESGCM(key).encrypt(nonce, plaintext, aad)


def parse_container(blob: bytes) -> tuple[dict, bytes, bytes]:
    """Returns (header, aad, ciphertext). Raises IntegrityError on malformed input."""
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise IntegrityError("Not a QuantumShield container (bad magic)")
    (n,) = struct.unpack(">I", blob[4:8])
    if n > (1 << 20) or 8 + n + 16 > len(blob):
        raise IntegrityError("Container truncated or header length invalid")
    try:
        hdr = json.loads(blob[8 : 8 + n])
        if not isinstance(hdr, dict):
            raise ValueError
    except ValueError as exc:
        raise IntegrityError("Header is not valid JSON") from exc
    return hdr, blob[: 8 + n], blob[8 + n :]


def decrypt(ident: Identity, blob: bytes, expected_mode: str | None = None) -> tuple[bytes, dict]:
    """Authenticated decryption. Returns (plaintext, header)."""
    hdr, aad, ct = parse_container(blob)
    mode = hdr.get("mode")
    if mode not in MODES:
        raise IntegrityError("Unknown or missing mode in header")
    if expected_mode is not None and expected_mode != mode:
        raise ModeMismatchError(
            f"Container was protected with '{mode}' but '{expected_mode}' was required"
        )
    try:
        fields = {k: base64.b64decode(hdr[k], validate=True) for k in _FIELDS[mode]}
        nonce = base64.b64decode(hdr["nonce"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise IntegrityError(f"Header lacks the fields required by '{mode}' mode") from exc
    if len(nonce) != 12 or len(fields.get("x25519_eph", b"x" * 32)) != 32 or len(
        fields.get("mlkem_ct", b"x" * SIZES["mlkem_ct"])
    ) != SIZES["mlkem_ct"]:
        raise IntegrityError("Header field has invalid length")
    key = recover(mode, ident, fields)
    try:
        return AESGCM(key).decrypt(nonce, ct, aad), hdr
    except InvalidTag as exc:
        raise IntegrityError(
            "Authentication failed: data was modified/corrupted or the wrong key was used"
        ) from exc


# ------------------------------------------------------------------- signatures
def sign(ident: Identity, message: bytes) -> bytes:
    return _dsa.sign(ident.dsa_sk, message)


def verify(dsa_pk: bytes, message: bytes, signature: bytes) -> bool:
    """True only if the ML-DSA-65 signature is valid. Malformed input -> False."""
    try:
        _dsa.verify(dsa_pk, message, signature)
        return True
    except ValueError:  # InvalidSignatureError and length errors are ValueErrors
        return False


# --------------------------------------------------------------------- keystore
def export_keystore(ident: Identity, passphrase: str) -> bytes:
    """Passphrase-protected private-key backup (scrypt + AES-256-GCM)."""
    if len(passphrase) < 8:
        raise ValueError("Passphrase must be at least 8 characters")
    blob = json.dumps(
        {
            "name": ident.name,
            "x_sk": _b64(ident.x_sk.private_bytes_raw()),
            "kem_sk": _b64(ident.kem_sk),
            "dsa_sk": _b64(ident.dsa_sk),
            "x_pub": _b64(ident.x_pub),
            "kem_pk": _b64(ident.kem_pk),
            "dsa_pk": _b64(ident.dsa_pk),
        }
    ).encode()
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
    ct = AESGCM(key).encrypt(nonce, blob, b"QSK1")
    return b"QSK1" + salt + nonce + ct


def import_keystore(data: bytes, passphrase: str) -> Identity:
    if data[:4] != b"QSK1" or len(data) < 4 + 16 + 12 + 16:
        raise IntegrityError("Not a QuantumShield keystore")
    salt, nonce, ct = data[4:20], data[20:32], data[32:]
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
    try:
        d = json.loads(AESGCM(key).decrypt(nonce, ct, b"QSK1"))
    except InvalidTag as exc:
        raise IntegrityError("Wrong passphrase or corrupted keystore") from exc
    b = base64.b64decode
    return Identity(
        d["name"], b(d["x_pub"]), b(d["kem_pk"]), b(d["dsa_pk"]),
        X25519PrivateKey.from_private_bytes(b(d["x_sk"])), b(d["kem_sk"]), b(d["dsa_sk"]),
    )
