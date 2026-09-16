"""Generic VBScript de-obfuscation: undoes a real, observed obfuscation technique
(pad every real character of a base64-encoded payload with a long, fixed junk
filler string, to defeat naive `strings`/YARA extraction) and reconstructs/decodes
the resulting blob. Pure text/byte manipulation -- no execution of any kind.
"""
from __future__ import annotations

import base64
import dataclasses
import re
from collections import Counter

_BASE64_ALPHABET_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")


@dataclasses.dataclass
class FillerStripResult:
    cleaned_text: str
    filler: str | None
    occurrences: int


def detect_and_strip_filler(text: str, min_repeats: int = 50) -> FillerStripResult:
    """Detects a single, highly-repeated 'filler' substring interspersed between
    base64-alphabet characters and strips it. Confirmed on a real sample: every
    single real base64 character of an embedded payload was followed by the exact
    same ~15-character junk Unicode filler, inflating a 4KB payload into an 18MB,
    10,000+-line file specifically to defeat naive string/YARA extraction.

    This assumes the hidden content is base64 (true of the observed technique and
    the most common "hide an embedded executable" case) -- it will not detect
    filler interspersed in non-base64-shaped hidden content.

    Deliberately conservative about what counts as a "filler" to avoid firing on
    ordinary code's own repetitive formatting (e.g. consistent indentation/newlines
    between short, coincidentally base64-alphabet-shaped tokens like variable
    names): the candidate must repeat at least `min_repeats` times AND either be
    reasonably long (>= 8 chars) or contain a non-ASCII/control character -- real
    formatting whitespace is short and plain-ASCII, so this excludes it while still
    catching the actual observed technique (a long, exotic-character filler).
    """
    gaps = [g for g in re.split(r"[A-Za-z0-9+/=]", text) if g]
    if not gaps:
        return FillerStripResult(text, None, 0)

    filler, count = Counter(gaps).most_common(1)[0]
    looks_deliberate = len(filler) >= 8 or any(ord(c) > 127 or ord(c) < 9 for c in filler)
    if count < min_repeats or not looks_deliberate:
        return FillerStripResult(text, None, 0)

    return FillerStripResult(text.replace(filler, ""), filler, count)


def extract_ordered_base64_chunks(text: str, min_chunk_len: int = 200) -> list[str]:
    """Long base64-alphabet runs, in the order they appear in the document -- a
    payload can be split across multiple adjacent string-literal chunks (VBS
    `a = a & "..."`-style concatenation), so document order must be preserved for
    concatenation to reconstruct the original bytes correctly."""
    return [m.group(0) for m in re.finditer(rf"[A-Za-z0-9+/=]{{{min_chunk_len},}}", text)]


def decode_concatenated_base64(chunks: list[str]) -> bytes | None:
    if not chunks:
        return None
    combined = "".join(chunks)
    padded = combined + "=" * (-len(combined) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (base64.binascii.Error, ValueError):
        return None


def reconstruct_embedded_payload(text: str, min_repeats: int = 20) -> tuple[bytes | None, FillerStripResult]:
    """Full pipeline: strip a detected junk filler (if any), then find and decode
    the longest run(s) of base64-alphabet characters. Returns (decoded_bytes_or_None,
    filler_strip_result) so the caller can report whether/what filler was found even
    if decoding itself doesn't produce anything useful."""
    strip_result = detect_and_strip_filler(text, min_repeats=min_repeats)
    chunks = extract_ordered_base64_chunks(strip_result.cleaned_text)
    decoded = decode_concatenated_base64(chunks)
    if decoded is not None and len(decoded) < 16:
        decoded = None
    return decoded, strip_result
