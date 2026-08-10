"""Deterministic unit tests for the modules this fork added.

All are network-free — they exercise the parsing/scoring/hashing logic directly,
so they prove the new code is correct without depending on live targets.
"""
from perimetry.modules import jarm_tls_fingerprint as jarm
from perimetry.modules import js_secret_scanner as secrets
from perimetry.modules import security_headers_grade as headers
from perimetry.modules import sri_integrity_checker as sri


# --- JARM TLS fingerprint -------------------------------------------------

def test_jarm_total_failure_is_all_zeros():
    assert jarm.jarm_hash(jarm.TOTAL_FAILURE) == "0" * 62


def test_jarm_cipher_byte_mapping():
    assert jarm.cipher_byte("") == "00"           # no cipher negotiated
    assert jarm.cipher_byte("0004") == "01"       # first entry in the index
    assert len(jarm.cipher_byte("c02b")) == 2     # always two hex chars


def test_jarm_version_byte_mapping():
    assert jarm.version_byte("") == "0"
    assert jarm.version_byte("0301") == "b"       # TLS 1.0 record
    assert jarm.version_byte("0303") == "d"       # TLS 1.2 record


def test_jarm_hash_shape_for_valid_input():
    raw = ",".join(["c02b|0303|h2|002b-0033"] * 10)
    fp = jarm.jarm_hash(raw)
    assert len(fp) == 62
    assert all(c in "0123456789abcdef" for c in fp)


# --- JS secret / API key scanner ------------------------------------------

def test_secret_scanner_detects_aws_key():
    blob = 'const c = { key: "AKIAIOSFODNN7EXAMPLE" };'
    findings = list(secrets.scan_text("app.js", blob, 3.0))
    labels = [f[2] for f in findings]
    assert "AWS Access Key ID" in labels
    aws = next(f for f in findings if f[2] == "AWS Access Key ID")
    assert aws[3] == "HIGH"


def test_secret_scanner_masks_the_value():
    masked = secrets.mask("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in masked   # never leak the raw secret
    assert "…" in masked and masked.startswith("AKIA")


def test_secret_scanner_ignores_plain_text():
    findings = list(secrets.scan_text("app.js", "const greeting = 'hello world';", 3.0))
    assert findings == []


# --- Security headers grade ------------------------------------------------

def test_headers_grade_boundaries():
    assert headers.grade_for(96) == "A+"
    assert headers.grade_for(85) == "A"
    assert headers.grade_for(60) == "D"
    assert headers.grade_for(10) == "F"


def test_headers_xcto_scoring():
    pts, maximum, _ = headers.eval_xcto("nosniff")
    assert (pts, maximum) == (10, 10)
    miss_pts, _, _ = headers.eval_xcto(None)
    assert miss_pts == 0


# --- Subresource integrity checker ----------------------------------------

def test_sri_collects_external_scripts_and_styles():
    html = (
        '<script src="https://cdn.example.org/a.js" integrity="sha384-x"></script>'
        '<script src="/local/b.js"></script>'
        '<link rel="stylesheet" href="https://cdn.example.org/s.css">'
        '<link rel="preload" href="https://cdn.example.org/skip.css">'
    )
    res = sri.collect_resources(html, "https://site.com/")
    urls = [r[1] for r in res]
    assert "https://cdn.example.org/a.js" in urls
    assert "https://cdn.example.org/s.css" in urls
    assert all("skip.css" not in u for u in urls)   # preload is not a stylesheet


def test_sri_is_external_detection():
    assert sri.is_external("https://cdn.other.com/x.js", "site.com") is True
    assert sri.is_external("https://site.com/x.js", "site.com") is False
    assert sri.is_external("https://www.site.com/x.js", "site.com") is False
