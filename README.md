# 🛡️ QuantumShield
Hybrid post-quantum secure communication and file protection — hackathon prototype.

| Feature | Implementation |
|---|---|
| Classical | X25519 → HKDF-SHA256 → AES-256-GCM (`cryptography`) |
| Post-quantum | **ML-KEM-768** (FIPS 203) → HKDF-SHA256 → AES-256-GCM |
| Hybrid | X25519 ‖ ML-KEM-768 secrets → one HKDF-SHA256 (binds mode + all public values) → AES-256-GCM. No fallback to classical. |
| Signatures | **ML-DSA-65** (FIPS 204) keygen / sign / verify / tamper detection |
| Files | Encrypt, download, decrypt; modified or corrupted data is rejected (AEAD) |
| Dashboard | Streamlit: home, messaging, files, signatures, comparison, performance, education |

ML-KEM and ML-DSA come from [`pqcrypto`](https://pypi.org/project/pqcrypto/) 1.0 (compiled PQClean C code).
Nothing is simulated with AES/RSA. Qiskit and IBM Quantum are **not** needed.

## Install (Ubuntu)
```bash
cd quantum-hackday
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
streamlit run app.py
```
Open http://localhost:8501. Start on **Home** and press **Run self-test**, then **Performance → Run benchmark**.

## Test
```bash
pip install -r requirements-dev.txt
python -m pytest -q
```
43 tests: round-trips for all modes, single-bit-flip tamper detection, truncation/garbage input, wrong recipient,
hybrid downgrade attempts (label change, stripped field, required-mode mismatch), signature tampering, keystore,
benchmarks, UI smoke tests, and **interoperability with independent pure-Python ML-KEM/ML-DSA implementations**
(`kyber-py`, `dilithium-py`) to confirm `pqcrypto` is genuine FIPS 203/204.

## Demo script (3 minutes)
1. **Home** → Run self-test (all PASS).
2. **Secure Messaging** → Hybrid → Encrypt → tick "flip one bit" → Decrypt → rejected. Untick → decrypts.
3. **Secure Messaging** → encrypt with Classical, then require Hybrid → refused (no downgrade).
4. **File Encryption** → upload any file → download `.qsh` → decrypt it; try the corruption checkbox.
5. **Digital Signatures** → Sign → Verify → tick tamper → invalid.
6. **Performance** → Run benchmark; **Classical vs PQC vs Hybrid** shows measured sizes.

## Layout
```
app.py          Streamlit UI            qs_crypto.py   all cryptography
bench.py        real measurements       tests/         pytest suite
```

## Honest limitations
Not audited, not production-ready. Python offers no constant-time guarantees. Encryption is "to a recipient" and does
not authenticate the sender (use ML-DSA separately). ML-KEM keys are long-term in the demo. No PKI/key distribution.
Keys live in session memory; use the sidebar keystore (scrypt + AES-256-GCM) to decrypt files after a restart.
Benchmarks are wall-clock Python timings on your machine, not a rigorous cryptographic benchmark.
