import base64

from vbssim_service.deobfuscate import (
    decode_concatenated_base64,
    detect_and_strip_filler,
    extract_ordered_base64_chunks,
    reconstruct_embedded_payload,
)
from vbssim_service.scanner import extract_powershell_invoke_literals, scan

# A synthetic, obviously-not-real filler pattern -- distinct from (and shorter than)
# the real ~15-character Unicode filler observed on the real sample, but shaped the
# same way: long, exotic characters, never legitimately appearing in ordinary code.
_SYNTHETIC_FILLER = "⬌༐᎟"

# A clearly-synthetic "file" (not a real executable) to embed and recover -- long
# enough that its base64 form exceeds extract_ordered_base64_chunks' default
# min_chunk_len (200), matching how a real embedded payload is always far longer
# than that in practice.
_SYNTHETIC_PAYLOAD = b"synthetic test payload, not a real executable. " * 5


def _interspersed(b64_text: str, filler: str) -> str:
    return filler.join(list(b64_text)) + filler


def test_detect_and_strip_filler_finds_real_shaped_filler():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    obfuscated = _interspersed(b64, _SYNTHETIC_FILLER)
    result = detect_and_strip_filler(obfuscated, min_repeats=10)
    assert result.filler == _SYNTHETIC_FILLER
    assert result.occurrences >= len(b64)
    assert base64.b64decode(result.cleaned_text + "=" * (-len(result.cleaned_text) % 4)) == _SYNTHETIC_PAYLOAD


def test_short_ascii_whitespace_is_not_treated_as_filler():
    # Regression guard: ordinary code formatting (short, plain-ASCII repeated
    # whitespace between coincidentally base64-alphabet-shaped tokens like variable
    # names) must not be misdetected as deliberate obfuscation.
    text = "\n".join(f"var{i} = 1" for i in range(200))
    result = detect_and_strip_filler(text, min_repeats=10)
    assert result.filler is None


def test_low_repeat_count_is_not_treated_as_filler():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    obfuscated = _interspersed(b64, _SYNTHETIC_FILLER)
    result = detect_and_strip_filler(obfuscated, min_repeats=10_000)
    assert result.filler is None


def test_extract_ordered_base64_chunks_preserves_document_order():
    # Non-hex letters: a pure-hex run is deliberately not treated as base64.
    text = "prefix " + ("G" * 250) + " middle " + ("H" * 250) + " suffix"
    chunks = extract_ordered_base64_chunks(text, min_chunk_len=200)
    assert chunks == ["G" * 250, "H" * 250]


def test_decode_concatenated_base64_handles_split_chunks():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    mid = len(b64) // 2
    decoded = decode_concatenated_base64([b64[:mid], b64[mid:]])
    assert decoded == _SYNTHETIC_PAYLOAD


def test_reconstruct_embedded_payload_end_to_end_with_filler():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    obfuscated = _interspersed(b64, _SYNTHETIC_FILLER)
    decoded, filler_result = reconstruct_embedded_payload(obfuscated, min_repeats=10)
    assert decoded == _SYNTHETIC_PAYLOAD
    assert filler_result.filler == _SYNTHETIC_FILLER


def test_reconstruct_embedded_payload_without_filler_still_works():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    decoded, filler_result = reconstruct_embedded_payload(b64, min_repeats=10)
    assert decoded == _SYNTHETIC_PAYLOAD
    assert filler_result.filler is None


# ---------------------------------------------------------------------------
# Scattered short-token filler (spliced within long runs, not between every
# single character) -- confirmed on a real sample: a custom "decode" function
# was called repeatedly with strings like "SYSTEMROddpfnIIOT", each carrying a
# short, mixed-case marker token scattered every few characters.
# ---------------------------------------------------------------------------

_SCATTERED_TOKEN = "qzTr9k"


def _splice_every_n(content: str, filler: str, n: int = 5) -> str:
    return filler.join(content[i:i + n] for i in range(0, len(content), n))


def test_detect_and_strip_filler_finds_scattered_token_within_runs():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    obfuscated = _splice_every_n(b64, _SCATTERED_TOKEN)
    result = detect_and_strip_filler(obfuscated, min_repeats=10)
    assert result.filler == _SCATTERED_TOKEN
    padded = result.cleaned_text + "=" * (-len(result.cleaned_text) % 4)
    assert base64.b64decode(padded) == _SYNTHETIC_PAYLOAD


def test_scattered_token_detector_ignores_diverse_ordinary_identifiers():
    # Regression guard: plenty of long-ish, distinct (never-repeated) identifiers
    # must not make any short substring look like a dominant, deliberate filler.
    text = "\n".join(f"variableNameNumber{i}CallSomethingElse" for i in range(300))
    result = detect_and_strip_filler(text, min_repeats=10)
    assert result.filler is None


# ---------------------------------------------------------------------------
# Per-line marker/prefix filler (a base64 blob split across many short lines,
# each carrying a repeated marker) -- confirmed on a real sample: a fake
# PowerShell/Authenticode "signature block" ("'' SIG '' <fragment>" on every
# line) was pasted into a *.vbs* file specifically to camouflage an embedded
# blob as a legitimate digital signature.
# ---------------------------------------------------------------------------

_LINE_MARKER = "~~MARK~~ "


def _wrap_as_marked_lines(b64_text: str, marker: str, width: int = 44) -> str:
    lines = [b64_text[i:i + width] for i in range(0, len(b64_text), width)]
    return "\n".join(f"{marker}{line}" for line in lines) + "\n"


def test_detect_and_strip_filler_finds_line_prefix_marker():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    obfuscated = _wrap_as_marked_lines(b64, _LINE_MARKER)
    result = detect_and_strip_filler(obfuscated, min_repeats=5)
    assert result.filler == _LINE_MARKER
    chunks = extract_ordered_base64_chunks(result.cleaned_text, min_chunk_len=len(b64))
    assert decode_concatenated_base64(chunks) == _SYNTHETIC_PAYLOAD


def test_line_prefix_marker_below_min_repeats_not_flagged():
    b64 = base64.b64encode(_SYNTHETIC_PAYLOAD).decode()
    obfuscated = _wrap_as_marked_lines(b64, _LINE_MARKER)
    result = detect_and_strip_filler(obfuscated, min_repeats=10_000)
    assert result.filler is None


def test_cleaned_text_reveals_findings_hidden_by_filler():
    # Real bug found on a live submission: the junk filler observed on a real
    # sample is interspersed through the *entire* script, not just the embedded
    # base64 payload -- so a reflective-invoke call site (and its candidate
    # ciphertext argument) is itself filler-obfuscated and invisible to scan()/
    # extract_powershell_invoke_literals() unless they're run against
    # filler_result.cleaned_text rather than the raw script text.
    script = 'powershell -Command "[AppDomain]::CurrentDomain.Load([Convert]::FromBase64String(\'' \
        + "A" * 250 + "'))\""
    obfuscated = _interspersed(script, _SYNTHETIC_FILLER)
    _, filler_result = reconstruct_embedded_payload(obfuscated, min_repeats=10)
    assert filler_result.filler == _SYNTHETIC_FILLER

    assert scan(obfuscated) == []
    assert extract_powershell_invoke_literals(obfuscated) == []

    kinds = [f.kind for f in scan(filler_result.cleaned_text)]
    assert "reflective_dotnet_load" in kinds
    assert extract_powershell_invoke_literals(filler_result.cleaned_text)
