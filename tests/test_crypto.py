import base64
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bench  # noqa: E402
import qs_crypto as qc  # noqa: E402
from pqcrypto.kem import ml_kem_768 as kem  # noqa: E402
from pqcrypto.sign import ml_dsa_65 as dsa  # noqa: E402


@pytest.fixture(scope="module")
def alice():
    return qc.generate_identity("alice")


# ------------------------------------------------ genuineness of ML-KEM / ML-DSA
def test_fips_sizes():
    assert (kem.PUBLIC_KEY_SIZE, kem.SECRET_KEY_SIZE, kem.CIPHERTEXT_SIZE, kem.SHARED_SECRET_SIZE) == (1184, 2400, 1088, 32)
    assert (dsa.PUBLIC_KEY_SIZE, dsa.SECRET_KEY_SIZE, dsa.SIGNATURE_SIZE) == (1952, 4032, 3309)


def test_mlkem_implicit_rejection():
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    bad = bytearray(ct)
    bad[5] ^= 1
    assert kem.decaps(sk, ct) == ss
    assert kem.decaps(sk, bytes(bad)) != ss  # FIPS 203: no error, different secret


def test_mlkem_interop_with_independent_implementation():
    ind = pytest.importorskip("kyber_py.ml_kem")
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    assert ind.ML_KEM_768.decaps(sk, ct) == ss
    ss2, ct2 = ind.ML_KEM_768.encaps(pk)
    assert kem.decaps(sk, ct2) == ss2


def test_mldsa_interop_with_independent_implementation():
    ind = pytest.importorskip("dilithium_py.ml_dsa")
    pk, sk = dsa.keygen()
    assert ind.ML_DSA_65.verify(pk, b"hello", dsa.sign(sk, b"hello"))
    dsa.verify(pk, b"hello", ind.ML_DSA_65.sign(sk, b"hello"))  # raises if invalid


# ------------------------------------------------------- encryption, all modes
@pytest.mark.parametrize("mode", qc.MODES)
def test_roundtrip(alice, mode):
    msg = os.urandom(5000)
    blob = qc.encrypt(mode, alice.public(), msg, "a.bin")
    pt, hdr = qc.decrypt(alice, blob, expected_mode=mode)
    assert pt == msg and hdr["mode"] == mode and hdr["filename"] == "a.bin"


@pytest.mark.parametrize("mode", qc.MODES)
def test_empty_plaintext(alice, mode):
    assert qc.decrypt(alice, qc.encrypt(mode, alice.public(), b""))[0] == b""


@pytest.mark.parametrize("mode", qc.MODES)
def test_ciphertext_is_randomised(alice, mode):
    assert qc.encrypt(mode, alice.public(), b"same") != qc.encrypt(mode, alice.public(), b"same")


@pytest.mark.parametrize("mode", qc.MODES)
def test_any_single_bit_flip_detected(alice, mode):
    blob = qc.encrypt(mode, alice.public(), b"attack at dawn")
    for pos in range(0, len(blob), max(1, len(blob) // 200)):  # sample across whole blob
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(qc.QSError):
            qc.decrypt(alice, bytes(bad))


@pytest.mark.parametrize("mode", qc.MODES)
def test_truncation_and_garbage_rejected(alice, mode):
    blob = qc.encrypt(mode, alice.public(), b"hello world")
    for bad in (blob[:-1], blob[:10], b"", b"garbage" * 10, blob + b"x"):
        with pytest.raises(qc.QSError):
            qc.decrypt(alice, bad)


@pytest.mark.parametrize("mode", qc.MODES)
def test_wrong_recipient_cannot_decrypt(alice, mode):
    bob = qc.generate_identity("bob")
    blob = qc.encrypt(mode, alice.public(), b"secret")
    with pytest.raises(qc.IntegrityError):
        qc.decrypt(bob, blob)


# ------------------------------------------------------- hybrid / no downgrade
def _rewrite_header(blob, **changes):
    hdr, _, ct = qc.parse_container(blob)
    for k, v in changes.items():
        if v is None:
            hdr.pop(k)
        else:
            hdr[k] = v
    hb = json.dumps(hdr, sort_keys=True, separators=(",", ":")).encode()
    return qc.MAGIC + struct.pack(">I", len(hb)) + hb + ct


def test_hybrid_requires_both_public_keys(alice):
    p = alice.public()
    with pytest.raises(qc.MissingKeyError):
        qc.encrypt("hybrid", qc.PublicBundle(p.x_pub, b"", p.dsa_pk), b"x")
    with pytest.raises(qc.MissingKeyError):
        qc.encrypt("hybrid", qc.PublicBundle(b"", p.kem_pk, p.dsa_pk), b"x")


def test_no_silent_downgrade_label_change(alice):
    blob = qc.encrypt("hybrid", alice.public(), b"x")
    for fake in ("classical", "pqc"):
        with pytest.raises(qc.IntegrityError):  # mode is in HKDF info + AAD
            qc.decrypt(alice, _rewrite_header(blob, mode=fake))


def test_no_silent_downgrade_field_stripped(alice):
    blob = qc.encrypt("hybrid", alice.public(), b"x")
    for field in ("x25519_eph", "mlkem_ct"):
        with pytest.raises(qc.IntegrityError):
            qc.decrypt(alice, _rewrite_header(blob, **{field: None}))


def test_expected_mode_enforced(alice):
    blob = qc.encrypt("classical", alice.public(), b"x")
    with pytest.raises(qc.ModeMismatchError):
        qc.decrypt(alice, blob, expected_mode="hybrid")


def test_hybrid_key_depends_on_both_secrets(alice):
    """Changing either component alone must change the derived key."""
    pub = alice.public()
    k_h, f = qc.establish("hybrid", pub)
    assert qc.recover("hybrid", alice, f) == k_h
    other = qc.generate_identity("o")
    f_bad_x = dict(f, x25519_eph=qc.x25519_keygen()[1])
    assert qc.recover("hybrid", alice, f_bad_x) != k_h
    f_bad_k = dict(f, mlkem_ct=kem.encaps(other.kem_pk)[0])
    assert qc.recover("hybrid", alice, f_bad_k) != k_h
    assert qc.recover("hybrid", alice, f) != qc.establish("classical", pub)[0]


def test_repr_does_not_leak_private_keys(alice):
    r = repr(alice)
    assert "x_sk" not in r and "kem_sk" not in r and "dsa_sk" not in r


# ------------------------------------------------------------------ signatures
def test_signature_roundtrip_and_sizes(alice):
    sig = qc.sign(alice, b"contract v1")
    assert len(sig) == 3309 and len(alice.dsa_pk) == 1952
    assert qc.verify(alice.dsa_pk, b"contract v1", sig)


def test_signature_tamper_detection(alice):
    sig = qc.sign(alice, b"contract v1")
    assert not qc.verify(alice.dsa_pk, b"contract v2", sig)  # message changed
    bad = bytearray(sig)
    bad[100] ^= 1
    assert not qc.verify(alice.dsa_pk, b"contract v1", bytes(bad))  # signature changed
    assert not qc.verify(qc.generate_identity("m").dsa_pk, b"contract v1", sig)  # wrong key
    assert not qc.verify(alice.dsa_pk, b"contract v1", sig[:50])  # malformed


# -------------------------------------------------------------------- keystore
def test_keystore_roundtrip(alice):
    ks = qc.export_keystore(alice, "correct horse battery")
    again = qc.import_keystore(ks, "correct horse battery")
    blob = qc.encrypt("hybrid", alice.public(), b"persisted")
    assert qc.decrypt(again, blob)[0] == b"persisted"
    with pytest.raises(qc.IntegrityError):
        qc.import_keystore(ks, "wrong passphrase!")
    with pytest.raises(ValueError):
        qc.export_keystore(alice, "short")


# ------------------------------------------------------------------- benchmarks
def test_benchmarks_produce_real_numbers():
    t = bench.run_timings(iterations=3, payload_sizes=(1024,))
    assert (t["median_ms"] > 0).all() and len(t) > 15
    s = bench.measure_sizes().set_index(["group", "metric"])["bytes"]
    assert s[("ML-KEM-768", "Public key")] == 1184
    assert s[("Hybrid", "Public key")] == 1184 + 32
    assert s[("ML-DSA-65", "Signature")] == 3309
    assert s[("Hybrid", "Key-exchange data sent (ciphertext)")] == 1088 + 32
