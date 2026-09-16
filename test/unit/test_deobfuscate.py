import base64

from vbssim_service.deobfuscate import (
    decode_concatenated_base64,
    detect_and_strip_filler,
    extract_ordered_base64_chunks,
    reconstruct_embedded_payload,
)

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
    text = "prefix " + ("A" * 250) + " middle " + ("B" * 250) + " suffix"
    chunks = extract_ordered_base64_chunks(text, min_chunk_len=200)
    assert chunks == ["A" * 250, "B" * 250]


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
