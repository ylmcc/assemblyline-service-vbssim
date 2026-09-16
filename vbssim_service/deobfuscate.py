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

# Candidate lengths tried by _detect_scattered_token_filler when hunting for a
# short marker token repeated *within* long alphanumeric runs.
_SCATTERED_CANDIDATE_LENGTHS = range(4, 17)
_MIN_RUN_LEN_FOR_SCATTERED = 10
_MAX_SCATTERED_SCAN_CHARS = 300_000

# A line ending in a run of 8+ base64-alphabet characters, with anything (incl.
# nothing) before it -- used to find a per-line marker/prefix repeated across many
# lines, each carrying a fragment of a longer base64 blob.
_LINE_MARKER_RE = re.compile(r"^(.*?)([A-Za-z0-9+/=]{8,})[ \t]*$")


@dataclasses.dataclass
class FillerStripResult:
    cleaned_text: str
    filler: str | None
    occurrences: int


def _looks_deliberately_random(token: str) -> bool:
    if len(set(token)) <= 1:
        return False
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    return (has_upper and has_lower) or has_digit


def _detect_uniform_intersperse_filler(text: str, min_repeats: int) -> FillerStripResult:
    """Detects a single, highly-repeated 'filler' substring interspersed between
    *every* base64-alphabet character and strips it. Confirmed on a real sample:
    every single real base64 character of an embedded payload was followed by the
    exact same ~15-character junk Unicode filler, inflating a 4KB payload into an
    18MB, 10,000+-line file specifically to defeat naive string/YARA extraction.

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


def _detect_scattered_token_filler(text: str, min_repeats: int) -> FillerStripResult:
    """Detects a short, literal marker token repeated many times *within* long
    base64/hex-alphabet runs (e.g. "SYSTEMROddpfnIIOT" -> "SYSTEMROOT") -- unlike
    _detect_uniform_intersperse_filler's whole-document gap-frequency count, here
    the filler only appears every few characters and is itself often shaped like
    valid base64-alphabet content, so it never surfaces as the most common "gap"
    between individual base64 characters. Confirmed on a real sample: a 7-char
    mixed-case token ("ddpfnII") was spliced into otherwise-plaintext/hex string
    literals passed to a custom "decode" function, assembled piece by piece into a
    PowerShell command line.

    Candidates are drawn from long (>= 10 char) alphanumeric runs only, and must
    (a) repeat often (>= min_repeats), (b) account for a substantial share
    (>= 10%) of the scanned content, and (c) actually recur *within* a single
    run at least 3 times -- an ordinary, legitimately-repeated identifier or
    shared prefix (e.g. many distinct "variableNameNumberN..." locals, or a
    common keyword like "TimeSerial") appears at most once per occurrence site,
    whereas a splice-in-place filler is repeated many times within the very run
    it pads, which is what actually distinguishes deliberate obfuscation here.
    """
    runs = [m.group(0) for m in re.finditer(rf"[A-Za-z0-9]{{{_MIN_RUN_LEN_FOR_SCATTERED},}}", text)]
    combined = "".join(runs)[:_MAX_SCATTERED_SCAN_CHARS]
    if len(combined) < min_repeats:
        return FillerStripResult(text, None, 0)

    best_token, best_coverage = None, 0
    for length in _SCATTERED_CANDIDATE_LENGTHS:
        counts = Counter(combined[i:i + length] for i in range(len(combined) - length + 1))
        if not counts:
            continue
        token, count = counts.most_common(1)[0]
        coverage = count * length
        if coverage > best_coverage:
            best_token, best_coverage = token, coverage

    if best_token is None or not _looks_deliberately_random(best_token):
        return FillerStripResult(text, None, 0)

    occurrences = text.count(best_token)
    max_per_run = max((run.count(best_token) for run in runs), default=0)
    if occurrences < min_repeats or best_coverage / len(combined) < 0.10 or max_per_run < 3:
        return FillerStripResult(text, None, 0)

    return FillerStripResult(text.replace(best_token, ""), best_token, occurrences)


def _detect_line_prefix_marker_filler(text: str, min_repeats: int) -> FillerStripResult:
    """Detects a short literal marker repeated as a per-line prefix immediately
    before a base64 fragment -- e.g. a fake PowerShell/VBS "signature block"
    ("'' SIG '' <base64...>" on every line, mimicking Set-AuthenticodeSignature's
    real trailing-comment format). Concatenating each line's payload fragment (in
    order, with the marker and line breaks removed) reconstructs the original
    base64 blob that was split across many separate short lines specifically to
    dodge a single long base64-run detector.

    Requires the marker to recur on at least `min_repeats` lines AND the
    recovered payload fragments to total at least 200 characters, so an ordinary
    handful of similarly-prefixed log/config lines doesn't get misidentified.
    """
    prefix_counts: Counter[str] = Counter()
    for line in text.splitlines():
        m = _LINE_MARKER_RE.match(line)
        if m and m.group(1):
            prefix_counts[m.group(1)] += 1

    if not prefix_counts:
        return FillerStripResult(text, None, 0)

    marker, count = prefix_counts.most_common(1)[0]
    if count < min_repeats:
        return FillerStripResult(text, None, 0)

    cleaned_lines = []
    total_payload_len = 0
    for line in text.splitlines():
        m = _LINE_MARKER_RE.match(line)
        if m and m.group(1) == marker:
            cleaned_lines.append(m.group(2))
            total_payload_len += len(m.group(2))
        else:
            cleaned_lines.append(line + "\n")

    if total_payload_len < 200:
        return FillerStripResult(text, None, 0)

    return FillerStripResult("".join(cleaned_lines), marker, count)


def detect_and_strip_filler(text: str, min_repeats: int = 50) -> FillerStripResult:
    """Tries each known filler-obfuscation shape in turn (uniform per-character
    interspersion, a short token scattered within long runs, then a per-line
    prefix marker) and returns the first one that matches."""
    for detector in (
        _detect_uniform_intersperse_filler,
        _detect_scattered_token_filler,
        _detect_line_prefix_marker_filler,
    ):
        result = detector(text, min_repeats)
        if result.filler:
            return result
    return FillerStripResult(text, None, 0)


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
