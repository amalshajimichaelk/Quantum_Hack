"""Real measurements only: wall-clock timing of the actual operations, sizes via len()."""
from __future__ import annotations

import os
import statistics
import time

import pandas as pd
from pqcrypto.kem import ml_kem_768 as kem
from pqcrypto.sign import ml_dsa_65 as dsa

import qs_crypto as qc


def _time(fn, n: int) -> dict:
    for _ in range(3):  # warm-up (not recorded): avoids cold-start/page-fault skew
        fn()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)  # ms
    return {
        "median_ms": statistics.median(samples),
        "mean_ms": statistics.fmean(samples),
        "stdev_ms": statistics.stdev(samples) if n > 1 else 0.0,
        "runs": n,
    }


def _time_interleaved(fns: dict, n: int) -> dict:
    """Time several callables round-robin in shuffled order each iteration, so every
    one sees the same allocator/cache state (avoids first-runner penalty)."""
    import random

    for fn in fns.values():
        for _ in range(3):
            fn()
    samples = {k: [] for k in fns}
    order = list(fns)
    for _ in range(n):
        random.shuffle(order)
        for k in order:
            t0 = time.perf_counter_ns()
            fns[k]()
            samples[k].append((time.perf_counter_ns() - t0) / 1e6)
    return {
        k: {"median_ms": statistics.median(v), "mean_ms": statistics.fmean(v),
            "stdev_ms": statistics.stdev(v) if n > 1 else 0.0, "runs": n}
        for k, v in samples.items()
    }


def run_timings(iterations: int = 50, payload_sizes=(1024, 1024 * 1024)) -> pd.DataFrame:
    ident = qc.generate_identity("bench")
    pub = ident.public()
    rows = []

    def add(group, op, fn, n=iterations):
        rows.append({"group": group, "operation": op, **_time(fn, n)})

    # Key generation
    add("Classical", "Key generation (X25519)", qc.x25519_keygen)
    add("ML-KEM-768", "Key generation", kem.keygen)
    add("Hybrid", "Key generation (X25519 + ML-KEM)", lambda: (qc.x25519_keygen(), kem.keygen()))

    # Raw KEM operations
    pk, sk = kem.keygen()
    ct, _ = kem.encaps(pk)
    add("ML-KEM-768", "Encapsulation", lambda: kem.encaps(pk))
    add("ML-KEM-768", "Decapsulation", lambda: kem.decaps(sk, ct))

    # Full key establishment incl. HKDF, sender and recipient
    for mode, name in (("classical", "Classical"), ("pqc", "ML-KEM-768"), ("hybrid", "Hybrid")):
        add(name, "Key establishment (sender, incl. HKDF)", lambda m=mode: qc.establish(m, pub))
        _, fields = qc.establish(mode, pub)
        add(name, "Key recovery (recipient, incl. HKDF)", lambda m=mode, f=fields: qc.recover(m, ident, f))

    # Full encrypt / decrypt pipeline per payload size
    for size in payload_sizes:
        data = os.urandom(size)
        label = f"{size // 1024} KiB" if size < 1024 * 1024 else f"{size // (1024 * 1024)} MiB"
        n = iterations if size <= 1024 else max(20, iterations // 2)
        names = {"classical": "Classical", "pqc": "ML-KEM-768", "hybrid": "Hybrid"}
        blobs = {m: qc.encrypt(m, pub, data) for m in names}
        for op, fns in (
            ("Encrypt", {m: (lambda m=m: qc.encrypt(m, pub, data)) for m in names}),
            ("Decrypt", {m: (lambda m=m: qc.decrypt(ident, blobs[m])) for m in names}),
        ):
            for m, r in _time_interleaved(fns, n).items():
                rows.append({"group": names[m], "operation": f"{op} {label} (full pipeline)", **r})

    # ML-DSA-65
    msg = os.urandom(1024)
    dpk, dsk = dsa.keygen()
    sig = dsa.sign(dsk, msg)
    add("ML-DSA-65", "Key generation", dsa.keygen)
    add("ML-DSA-65", "Sign 1 KiB", lambda: dsa.sign(dsk, msg))
    add("ML-DSA-65", "Verify 1 KiB", lambda: dsa.verify(dpk, msg, sig))
    return pd.DataFrame(rows)


def measure_sizes() -> pd.DataFrame:
    """Sizes in bytes, taken from real generated objects."""
    ident = qc.generate_identity("sizes")
    pub = ident.public()
    msg = b"x"
    overhead = {m: len(qc.encrypt(m, pub, b"")) for m in qc.MODES}  # empty plaintext
    _, f_c = qc.establish("classical", pub)
    _, f_p = qc.establish("pqc", pub)
    _, f_h = qc.establish("hybrid", pub)
    sig = qc.sign(ident, msg)
    rows = [
        ("Classical", "Public key", len(ident.x_pub)),
        ("ML-KEM-768", "Public key", len(ident.kem_pk)),
        ("Hybrid", "Public key", len(ident.x_pub) + len(ident.kem_pk)),
        ("Classical", "Key-exchange data sent (ciphertext)", sum(map(len, f_c.values()))),
        ("ML-KEM-768", "Key-exchange data sent (ciphertext)", sum(map(len, f_p.values()))),
        ("Hybrid", "Key-exchange data sent (ciphertext)", sum(map(len, f_h.values()))),
        ("Classical", "Container overhead (empty plaintext)", overhead["classical"]),
        ("ML-KEM-768", "Container overhead (empty plaintext)", overhead["pqc"]),
        ("Hybrid", "Container overhead (empty plaintext)", overhead["hybrid"]),
        ("ML-DSA-65", "Public key", len(ident.dsa_pk)),
        ("ML-DSA-65", "Signature", len(sig)),
    ]
    return pd.DataFrame(rows, columns=["group", "metric", "bytes"])
