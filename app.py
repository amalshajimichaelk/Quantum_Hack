"""QuantumShield - Streamlit dashboard. Run: streamlit run app.py"""
from __future__ import annotations

import os
import platform
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

import bench
import qs_crypto as qc

st.set_page_config(page_title="QuantumShield", page_icon="🛡️", layout="wide")

COLORS = {"Classical": "#8fa3c7", "ML-KEM-768": "#f5a524", "Hybrid": "#2dd4bf", "ML-DSA-65": "#c084fc"}
MODE_NAME = {"classical": "Classical", "pqc": "ML-KEM-768", "hybrid": "Hybrid"}
MODE_PICK = {
    "Classical  (X25519)": "classical",
    "Post-quantum  (ML-KEM-768)": "pqc",
    "Hybrid  (X25519 + ML-KEM-768)": "hybrid",
}

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, [class*="css"], .stMarkdown { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
code, pre, .mono { font-family: 'JetBrains Mono', ui-monospace, monospace !important; }
.block-container { padding-top: 2rem; max-width: 1200px; }
h1, h2, h3 { letter-spacing: -0.01em; }
.hero { padding: 1.6rem 1.8rem; border: 1px solid #1f2d4a; border-radius: 14px;
  background: linear-gradient(135deg, #0f1a33 0%, #0a1226 60%, #0d2230 100%); margin-bottom: 1.2rem; }
.hero h1 { margin: 0 0 .4rem 0; font-size: 2.1rem; }
.hero p { color: #a9b8d6; margin: 0; max-width: 62ch; line-height: 1.55; }
.card { border: 1px solid #1f2d4a; border-radius: 12px; padding: 1rem 1.1rem; background: #0f172b; height: 100%; }
.card h4 { margin: 0 0 .35rem 0; font-size: 1rem; }
.card p, .card li { color: #a9b8d6; font-size: .92rem; line-height: 1.5; margin: 0; }
.pill { display:inline-block; padding: 2px 10px; border-radius: 999px; font-size: .78rem; font-weight: 600; border: 1px solid; }
.ok   { color:#34d399; border-color:#34d399; background:#34d3991a; }
.bad  { color:#f87171; border-color:#f87171; background:#f871711a; }
.warn { color:#fbbf24; border-color:#fbbf24; background:#fbbf241a; }
.kv { display:flex; justify-content:space-between; gap:1rem; padding:.3rem 0; border-bottom:1px solid #1a2744; font-size:.9rem; }
.kv span:first-child { color:#8d9dbd; }
div[data-testid="stMetric"] { background:#0f172b; border:1px solid #1f2d4a; border-radius:12px; padding:.7rem .9rem; }
</style>
""",
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------- helpers
def pill(text: str, kind: str = "ok") -> str:
    return f'<span class="pill {kind}">{text}</span>'


def kv(rows: list[tuple[str, str]]) -> None:
    st.markdown("".join(f'<div class="kv"><span>{k}</span><span class="mono">{v}</span></div>' for k, v in rows), unsafe_allow_html=True)


def human(n: int) -> str:
    return f"{n:,} B" if n < 10_000 else f"{n / 1024:,.1f} KiB" if n < 10 * 1024 * 1024 else f"{n / 1048576:,.1f} MiB"


def flip_ciphertext_bit(blob: bytes) -> bytes:
    """Demo helper: flip one bit inside the AEAD ciphertext region."""
    _, aad, ct = qc.parse_container(blob)
    pos = len(aad) + max(0, (len(ct) - 16) // 2)
    b = bytearray(blob)
    b[pos] ^= 0x01
    return bytes(b)


def flip_text(data: bytes) -> bytes:
    b = bytearray(data or b"\x00")
    b[0] ^= 0x01
    return bytes(b)


def error_box(exc: Exception) -> None:
    st.markdown(pill("DECRYPTION REJECTED", "bad"), unsafe_allow_html=True)
    st.error(str(exc))


def get_identity() -> qc.Identity:
    if "ident" not in st.session_state:
        t = time.perf_counter()
        st.session_state.ident = qc.generate_identity("Recipient")
        st.session_state.ident_ms = (time.perf_counter() - t) * 1000
    return st.session_state.ident


def pick_input(key: str, label: str = "Data") -> tuple[bytes, str]:
    """Text or file input -> (bytes, name)."""
    src = st.radio(f"{label} source", ["Text", "File"], horizontal=True, key=f"{key}_src")
    if src == "Text":
        return st.text_area(label, "Transfer approved: 250,000 to account 4471.", key=f"{key}_txt", height=100).encode(), "message.txt"
    up = st.file_uploader(label, key=f"{key}_file")
    return (up.getvalue(), up.name) if up else (b"", "")


# ---------------------------------------------------------------------- sidebar
ident = get_identity()
with st.sidebar:
    st.markdown("## 🛡️ QuantumShield")
    st.caption("Hybrid post-quantum protection · hackathon prototype")
    page = st.radio(
        "Navigate",
        ["Home", "Secure Messaging", "File Encryption", "Digital Signatures", "Classical vs PQC vs Hybrid", "Performance", "About PQC"],
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown("**Session identity** (keys live in memory only)")
    kv([("Fingerprint", ident.fingerprint()), ("X25519 pub", f"{len(ident.x_pub)} B"), ("ML-KEM pub", f"{len(ident.kem_pk)} B"), ("ML-DSA pub", f"{len(ident.dsa_pk)} B")])
    st.caption("Private keys are never displayed.")
    if st.button("Generate new identity", width="stretch"):
        st.session_state.pop("ident")
        for k in ("msg_blob", "file_blob", "sig"):
            st.session_state.pop(k, None)
        st.rerun()
    with st.expander("Backup / restore keys"):
        pw = st.text_input("Passphrase (min 8 chars)", type="password", key="ks_pw")
        if pw and len(pw) >= 8:
            st.download_button("Download encrypted keystore", qc.export_keystore(ident, pw), "quantumshield.qsk", width="stretch")
        up = st.file_uploader("Restore keystore (.qsk)", key="ks_up")
        if up and pw and st.button("Restore", width="stretch"):
            try:
                st.session_state.ident = qc.import_keystore(up.getvalue(), pw)
                st.rerun()
            except qc.QSError as e:
                st.error(str(e))
        st.caption("scrypt + AES-256-GCM protected. Needed to decrypt files after a restart.")


# ------------------------------------------------------------------------- pages
def selftest() -> list[tuple[str, bool, str]]:
    out = []
    pub = ident.public()
    for m in qc.MODES:
        blob = qc.encrypt(m, pub, b"selftest")
        ok = qc.decrypt(ident, blob, m)[0] == b"selftest"
        out.append((f"{MODE_NAME[m]} encrypt/decrypt round-trip", ok, qc.MODE_LABEL[m]))
        try:
            qc.decrypt(ident, flip_ciphertext_bit(blob))
            out.append((f"{MODE_NAME[m]} tamper detection", False, "modification NOT detected"))
        except qc.IntegrityError:
            out.append((f"{MODE_NAME[m]} tamper detection", True, "modified ciphertext rejected"))
    try:
        qc.decrypt(ident, qc.encrypt("classical", pub, b"x"), expected_mode="hybrid")
        out.append(("Hybrid downgrade refused", False, "accepted a classical container"))
    except qc.ModeMismatchError:
        out.append(("Hybrid downgrade refused", True, "classical container rejected when hybrid required"))
    sig = qc.sign(ident, b"selftest")
    out.append(("ML-DSA-65 sign/verify", qc.verify(ident.dsa_pk, b"selftest", sig), f"{len(sig):,} B signature"))
    out.append(("ML-DSA-65 tamper detection", not qc.verify(ident.dsa_pk, b"selftesT", sig), "altered message rejected"))
    return out


def page_home():
    st.markdown(
        """<div class="hero"><h1>Encrypted today, readable tomorrow?</h1>
<p>Adversaries can record encrypted traffic now and decrypt it once a large enough quantum computer exists.
QuantumShield shows the upgrade path: NIST-standardised ML-KEM-768 and ML-DSA-65, combined with X25519 in a hybrid
mode so protection never depends on a single algorithm.</p></div>""",
        unsafe_allow_html=True,
    )
    c = st.columns(4)
    for col, (t, d, s) in zip(
        c,
        [
            ("Classical", "X25519 + HKDF-SHA256 + AES-256-GCM. Fast, small, but built on discrete-log hardness.", "RFC 7748 / 5869 / SP 800-38D"),
            ("Post-quantum", "ML-KEM-768 key encapsulation feeding HKDF-SHA256 and AES-256-GCM.", "FIPS 203"),
            ("Hybrid", "Both secrets go through one HKDF. An attacker has to break both algorithms.", "X25519 ‖ ML-KEM-768"),
            ("Signatures", "ML-DSA-65 signs and verifies messages and files; any change is detected.", "FIPS 204"),
        ],
    ):
        col.markdown(f'<div class="card"><h4>{t}</h4><p>{d}</p><p class="mono" style="margin-top:.6rem;color:#2dd4bf">{s}</p></div>', unsafe_allow_html=True)

    st.markdown("### Live self-test")
    st.caption("Runs every cryptographic operation right now with this session's keys.")
    if st.button("Run self-test", type="primary"):
        results = selftest()
        st.session_state.self = results
    for name, ok, detail in st.session_state.get("self", []):
        st.markdown(f'{pill("PASS" if ok else "FAIL", "ok" if ok else "bad")} &nbsp; **{name}** <span style="color:#8d9dbd">— {detail}</span>', unsafe_allow_html=True)
    st.info("Prototype for demonstration. Not audited and not production-ready. See **About PQC** for what is and is not covered.")


def page_messaging():
    st.title("Secure messaging")
    st.caption("Encrypt to the session identity's public keys, then decrypt with its private keys.")
    mode_label = st.radio("Algorithm", list(MODE_PICK), horizontal=True, key="msg_mode")
    mode = MODE_PICK[mode_label]
    st.caption(f"Pipeline: **{qc.MODE_LABEL[mode]}**")
    text = st.text_area("Message", "Meet at 09:00. Launch code is in the vault.", height=110)
    if st.button("🔒 Encrypt", type="primary"):
        t0 = time.perf_counter()
        blob = qc.encrypt(mode, ident.public(), text.encode(), "message")
        st.session_state.msg_blob = blob
        st.session_state.msg_enc_ms = (time.perf_counter() - t0) * 1000
        st.session_state.msg_mode_used = mode
    blob = st.session_state.get("msg_blob")
    if not blob:
        return
    hdr, aad, ct = qc.parse_container(blob)
    a, b = st.columns(2)
    with a:
        st.markdown("#### Encrypted")
        st.markdown(pill("ENCRYPTED · AES-256-GCM authenticated", "ok") + " " + pill(hdr["mode"].upper(), "warn"), unsafe_allow_html=True)
        kv([("Container size", human(len(blob))), ("Header (public)", human(len(aad))), ("Ciphertext + tag", human(len(ct))),
            ("Encrypt time", f"{st.session_state.msg_enc_ms:.2f} ms")])
        st.code(ct.hex()[:160] + ("…" if len(ct) * 2 > 160 else ""), language=None)
        st.download_button("Download container", blob, "message.qsh")
    with b:
        st.markdown("#### Decrypt")
        tamper = st.checkbox("Simulate attacker: flip one bit of the ciphertext")
        st.caption("Decryption requires the algorithm selected above. A container made with a weaker mode is refused, never downgraded.")
        if st.button("🔓 Decrypt"):
            data = flip_ciphertext_bit(blob) if tamper else blob
            try:
                t0 = time.perf_counter()
                pt, h = qc.decrypt(ident, data, expected_mode=mode)
                ms = (time.perf_counter() - t0) * 1000
                st.markdown(pill("VERIFIED · INTEGRITY OK", "ok"), unsafe_allow_html=True)
                st.success(pt.decode(errors="replace"))
                st.caption(f"Decrypted in {ms:.2f} ms using {h['mode']} mode")
            except qc.QSError as e:
                error_box(e)


def page_files():
    st.title("File encryption")
    enc, dec = st.tabs(["Encrypt a file", "Decrypt a file"])
    with enc:
        mode = MODE_PICK[st.radio("Algorithm", list(MODE_PICK), horizontal=True, key="f_mode")]
        up = st.file_uploader("File to protect", key="f_up")
        if up and st.button("🔒 Encrypt file", type="primary"):
            data = up.getvalue()
            t0 = time.perf_counter()
            blob = qc.encrypt(mode, ident.public(), data, up.name)
            st.session_state.file_blob = (blob, up.name, len(data), (time.perf_counter() - t0) * 1000, mode)
        if "file_blob" in st.session_state:
            blob, name, n, ms, m = st.session_state.file_blob
            st.markdown(pill("ENCRYPTED · AES-256-GCM authenticated", "ok"), unsafe_allow_html=True)
            kv([("Original", f"{name} · {human(n)}"), ("Encrypted", human(len(blob))), ("Overhead", human(len(blob) - n)), ("Mode", m), ("Time", f"{ms:.1f} ms")])
            st.download_button("⬇ Download encrypted file", blob, name + ".qsh", type="primary")
            st.caption("The filename is stored in the (authenticated but unencrypted) header.")
    with dec:
        req = MODE_PICK[st.radio("Required algorithm", list(MODE_PICK), horizontal=True, key="fd_mode")]
        up = st.file_uploader("Encrypted file (.qsh)", key="fd_up")
        corrupt = st.checkbox("Simulate corruption: flip one bit before decrypting", key="fd_corrupt")
        if up and st.button("🔓 Decrypt file", type="primary"):
            data = up.getvalue()
            try:
                if corrupt:
                    data = flip_ciphertext_bit(data)
                t0 = time.perf_counter()
                pt, h = qc.decrypt(ident, data, expected_mode=req)
                ms = (time.perf_counter() - t0) * 1000
                st.markdown(pill("VERIFIED · INTEGRITY OK", "ok"), unsafe_allow_html=True)
                st.caption(f"{human(len(pt))} recovered in {ms:.1f} ms · mode {h['mode']}")
                st.download_button("⬇ Download decrypted file", pt, h.get("filename") or "decrypted.bin", type="primary")
            except qc.QSError as e:
                error_box(e)
        st.caption("Files can only be decrypted with this session's identity (or a restored keystore).")


def page_signatures():
    st.title("Digital signatures · ML-DSA-65")
    st.caption("FIPS 204 lattice-based signatures. Signing uses the session identity's private key; verification needs only the public key.")
    sign_t, ver_t = st.tabs(["Sign", "Verify"])
    with sign_t:
        data, name = pick_input("sg", "Content to sign")
        if data and st.button("✍️ Sign with ML-DSA-65", type="primary"):
            t0 = time.perf_counter()
            sig = qc.sign(ident, data)
            st.session_state.sig = (sig, name, (time.perf_counter() - t0) * 1000)
        if "sig" in st.session_state:
            sig, nm, ms = st.session_state.sig
            st.markdown(pill("SIGNED", "ok"), unsafe_allow_html=True)
            kv([("Signature size", f"{len(sig):,} B"), ("Public key size", f"{len(ident.dsa_pk):,} B"), ("Sign time", f"{ms:.2f} ms")])
            c1, c2 = st.columns(2)
            c1.download_button("⬇ Signature (.sig)", sig, "content.sig", width="stretch")
            c2.download_button("⬇ Public key (.pub)", ident.dsa_pk, "mldsa65.pub", width="stretch")
    with ver_t:
        data, _ = pick_input("vf", "Content to verify")
        sig_up = st.file_uploader("Signature (.sig) — leave empty to use the last one you created", key="vf_sig")
        sig = sig_up.getvalue() if sig_up else (st.session_state.sig[0] if "sig" in st.session_state else b"")
        pk_up = st.file_uploader("Signer's public key (.pub) — leave empty for this session's key", key="vf_pk")
        pk = pk_up.getvalue() if pk_up else ident.dsa_pk
        tamper = st.checkbox("Simulate attacker: alter the content by one bit")
        if st.button("🔍 Verify signature", type="primary"):
            if not sig:
                st.warning("No signature available. Sign something first or upload a .sig file.")
            else:
                ok = qc.verify(pk, flip_text(data) if tamper else data, sig)
                if ok:
                    st.markdown(pill("SIGNATURE VALID", "ok"), unsafe_allow_html=True)
                    st.success("Content is authentic and unmodified.")
                else:
                    st.markdown(pill("SIGNATURE INVALID", "bad"), unsafe_allow_html=True)
                    st.error("Verification failed: content or signature was altered, or the key is wrong.")


def _sizes() -> pd.DataFrame:
    if "sizes" not in st.session_state:
        st.session_state.sizes = bench.measure_sizes()
    return st.session_state.sizes


def page_compare():
    st.title("Classical vs PQC vs Hybrid")
    sz = _sizes().set_index(["group", "metric"])["bytes"]
    rows = []
    for g, std, pq, note in [
        ("Classical", "X25519 (RFC 7748)", "No: broken by Shor's algorithm on a large fault-tolerant quantum computer", "Fast and compact; no post-quantum protection"),
        ("ML-KEM-768", "FIPS 203", "Designed to resist known quantum attacks (NIST category 3)", "Newer math; less cryptanalysis history than X25519"),
        ("Hybrid", "X25519 + ML-KEM-768", "Designed to resist: secure while either component holds", "Largest handshake; hedges against flaws in either algorithm"),
    ]:
        rows.append({
            "Mode": g, "Standard": std,
            "Public key (B)": int(sz[(g, "Public key")]),
            "Key-exchange data (B)": int(sz[(g, "Key-exchange data sent (ciphertext)")]),
            "Container overhead (B)": int(sz[(g, "Container overhead (empty plaintext)")]),
            "Quantum resistance": pq, "Trade-off": note,
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.caption("Byte sizes are measured from real generated keys and containers in this session.")
    if "timings" in st.session_state:
        t = st.session_state.timings
        t = t[t.operation.str.startswith("Key establishment (sender")][["group", "median_ms"]]
        fig = px.bar(t, x="group", y="median_ms", color="group", color_discrete_map=COLORS, title="Key establishment, sender side (median ms, measured)", template="plotly_dark")
        fig.update_layout(showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", xaxis_title=None, yaxis_title="ms")
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("Run the benchmark on the **Performance** page to add timing comparisons here.")
    st.markdown("#### Live side-by-side")
    msg = st.text_input("Message", "Hello, post-quantum world")
    cols = st.columns(3)
    for col, m in zip(cols, qc.MODES):
        blob = qc.encrypt(m, ident.public(), msg.encode())
        _, _, ct = qc.parse_container(blob)
        with col:
            st.markdown(f"**{MODE_NAME[m]}**")
            kv([("Container", f"{len(blob)} B"), ("Ciphertext+tag", f"{len(ct)} B")])
            st.code(ct.hex()[:48] + "…", language=None)


def page_perf():
    st.title("Performance")
    st.caption("Real wall-clock measurements on this machine (Python, single process, includes interpreter overhead). Nothing here is pre-filled.")
    n = st.slider("Iterations per operation", 10, 200, 50, step=10)
    if st.button("▶ Run benchmark", type="primary"):
        with st.spinner("Measuring…"):
            st.session_state.timings = bench.run_timings(n)
            st.session_state.bench_meta = f"{platform.platform()} · Python {platform.python_version()} · {os.cpu_count()} CPUs · {datetime.now():%Y-%m-%d %H:%M:%S} · {n} iterations (median reported)"
    if "timings" not in st.session_state:
        st.info("Press **Run benchmark**. It takes a few seconds.")
        st.dataframe(_sizes().rename(columns={"bytes": "size (B)"}), hide_index=True, width="stretch")
        return
    t = st.session_state.timings
    st.caption(st.session_state.bench_meta)
    log = st.checkbox("Logarithmic scale (X25519 runs in microseconds, ML-DSA in milliseconds)", value=True)

    def chart(df, x, title, y="median_ms", ylab="ms (median)"):
        fig = px.bar(df, x=x, y=y, color="group", barmode="group", color_discrete_map=COLORS, title=title, template="plotly_dark")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", yaxis_title=ylab, xaxis_title=None, legend_title=None)
        if log and y == "median_ms":
            fig.update_yaxes(type="log")
        st.plotly_chart(fig, width="stretch")

    c1, c2 = st.columns(2)
    with c1:
        chart(t[t.operation.str.contains("Key generation|Encapsulation|Decapsulation") & (t.group != "ML-DSA-65")], "operation", "Key generation and KEM operations")
    with c2:
        chart(t[t.operation.str.startswith(("Key establishment", "Key recovery"))], "operation", "Key establishment incl. HKDF")
    enc = t[t.operation.str.contains("crypt .* \\(full")]
    chart(enc, "operation", "Encrypt / decrypt, full pipeline (KEM + HKDF + AES-256-GCM)")
    c3, c4 = st.columns(2)
    s = _sizes()
    with c3:
        chart(s[s.metric.str.contains("Public key")], "group", "Public key sizes", "bytes", "bytes")
    with c4:
        chart(s[s.metric.isin(["Key-exchange data sent (ciphertext)", "Signature"])], "metric", "Ciphertext and signature sizes", "bytes", "bytes")
    chart(t[t.group == "ML-DSA-65"], "operation", "ML-DSA-65 operations")
    with st.expander("Raw measurements"):
        st.dataframe(t.round(4), hide_index=True, width="stretch")
        st.download_button("Download CSV", t.to_csv(index=False), "quantumshield_benchmark.csv")


def page_about():
    st.title("About post-quantum cryptography")
    c1, c2 = st.columns(2)
    c1.markdown("""
#### The threat
- **Shor's algorithm** would break RSA, Diffie-Hellman and elliptic-curve cryptography (including X25519 and ECDSA) on a large fault-tolerant quantum computer. Such machines do not exist today.
- **Grover's algorithm** gives only a quadratic speed-up against symmetric keys, so AES-256 remains a sound choice.
- **Harvest now, decrypt later:** data recorded today can be attacked in the future. Long-lived secrets need protection before the hardware arrives.

#### The standards (NIST, August 2024)
- **FIPS 203 · ML-KEM** (from CRYSTALS-Kyber): key encapsulation. We use ML-KEM-768.
- **FIPS 204 · ML-DSA** (from CRYSTALS-Dilithium): digital signatures. We use ML-DSA-65.
- **FIPS 205 · SLH-DSA** (from SPHINCS+): hash-based signatures, not used here.
""")
    c2.markdown("""
#### Why hybrid?
New algorithms have had less scrutiny than X25519. The hybrid mode feeds **both** shared secrets into a single HKDF-SHA256, together with the mode and all public values. The AES key stays safe if either algorithm survives.
A hybrid container never degrades: a missing component, a changed mode label or a mode mismatch makes decryption fail.

#### What this prototype does
- Uses `cryptography` (X25519, HKDF, AES-256-GCM, scrypt) and `pqcrypto` (PQClean ML-KEM-768 and ML-DSA-65). No algorithm is hand-written or simulated.
- Authenticates the whole container header as AEAD associated data.
- Cross-checks `pqcrypto` against an independent implementation in the test suite.

#### What it does not do
- **Not audited or production-ready.** No side-channel or constant-time guarantees from Python.
- Encryption is one-way "to a recipient": **it does not authenticate the sender**. Sign separately with ML-DSA.
- ML-KEM keys are long-term in this demo, so there is no post-compromise forward secrecy for them. Only the X25519 part uses ephemeral keys.
- No key distribution, PKI or certificate binding between the KEM and signature keys.
- Keys exist in memory for the session; the keystore export is the only persistence.
""")


{
    "Home": page_home,
    "Secure Messaging": page_messaging,
    "File Encryption": page_files,
    "Digital Signatures": page_signatures,
    "Classical vs PQC vs Hybrid": page_compare,
    "Performance": page_perf,
    "About PQC": page_about,
}[page]()
