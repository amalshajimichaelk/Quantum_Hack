import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from streamlit.testing.v1 import AppTest  # noqa: E402

PAGES = ["Home", "Secure Messaging", "File Encryption", "Digital Signatures",
         "Classical vs PQC vs Hybrid", "Performance", "About PQC"]
APP = os.path.join(os.path.dirname(__file__), "..", "app.py")


def fresh(page):
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, [e.value for e in at.exception]
    return at


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders(page):
    fresh(page)


def test_selftest_all_pass():
    at = fresh("Home")
    next(b for b in at.button if b.label == "Run self-test").click().run()
    assert not at.exception
    md = " ".join(m.value for m in at.markdown)
    assert "PASS" in md and "FAIL" not in md.replace("FAILED", "")


def test_message_encrypt_decrypt_and_tamper():
    at = fresh("Secure Messaging")
    next(b for b in at.button if "Encrypt" in b.label).click().run()
    next(b for b in at.button if "Decrypt" in b.label).click().run()
    assert not at.exception
    assert any("Meet at 09:00" in s.value for s in at.success)
    at.checkbox[0].check().run()
    next(b for b in at.button if "Decrypt" in b.label).click().run()
    assert any("Authentication failed" in e.value for e in at.error)


def test_signature_sign_and_verify_and_tamper():
    at = fresh("Digital Signatures")
    next(b for b in at.button if "Sign with" in b.label).click().run()
    assert "sig" in at.session_state
    next(b for b in at.button if "Verify" in b.label).click().run()
    assert any("authentic" in s.value for s in at.success)
    at.checkbox[0].check().run()
    next(b for b in at.button if "Verify" in b.label).click().run()
    assert any("Verification failed" in e.value for e in at.error)


def test_benchmark_runs():
    at = fresh("Performance")
    at.slider[0].set_value(10)
    next(b for b in at.button if "Run benchmark" in b.label).click().run()
    assert not at.exception
    assert len(at.session_state["timings"]) > 15
