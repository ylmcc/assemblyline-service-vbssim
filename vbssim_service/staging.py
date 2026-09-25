"""Static recovery of a script payload that a VBS dropper assembles in a string
variable and hands to another interpreter through a process environment variable,
rather than ever writing it to disk or passing it on a command line.

Confirmed on a real sample: a ~9KB PowerShell script was built from ~60
`Unrelative = Unrelative & "..."` literal fragments; the statements that consumed
it were themselves hidden in hex-encoded, XOR-keyed strings passed to a custom
decoder function and then to `Execute`:

    Shell.Environment("Process").Item("SOMEVAR") = Unrelative
    Shell.Run("cmd.exe /v:on /c echo ^%SOMEVAR^% | !OTHERVAR! -", 0)

-- i.e. `cmd` echoes the variable into PowerShell's stdin (`-`). No existing
service extracted the script as a file, because the only place it existed as a
whole was a runtime string.

Pure text manipulation -- nothing here evaluates or executes script content.
"""
from __future__ import annotations

import dataclasses
import re

# ---------------------------------------------------------------------------
# Literal string accumulation: `X = "..."`, `X = X & "..." & "..."`
# ---------------------------------------------------------------------------

_ASSIGNMENT_RE = re.compile(r"^\s*(?:Set\s+)?([A-Za-z_]\w*)\s*=\s*(.+?)\s*$", re.IGNORECASE)
_NAMED_CONSTANTS = {"vbcrlf": "\r\n", "vbnewline": "\r\n", "vblf": "\n", "vbcr": "\r", "vbtab": "\t"}
_CHR_RE = re.compile(r"ChrW?\(\s*(\d{1,5})\s*\)", re.IGNORECASE)


@dataclasses.dataclass
class AccumulatedString:
    name: str
    value: str
    fragments: int


def _split_concat_terms(rhs: str) -> list[str] | None:
    """Splits a VBS expression on top-level `&`/`+`, respecting `"..."` literals
    (with `""` as an escaped quote). Returns None on an unterminated literal."""
    terms, current, i, in_str = [], [], 0, False
    while i < len(rhs):
        c = rhs[i]
        if in_str:
            current.append(c)
            if c == '"':
                if i + 1 < len(rhs) and rhs[i + 1] == '"':
                    current.append('"')
                    i += 1
                else:
                    in_str = False
        elif c == '"':
            in_str = True
            current.append(c)
        elif c in "&+":
            terms.append("".join(current).strip())
            current = []
        elif c == "'":
            break  # trailing comment
        else:
            current.append(c)
        i += 1
    if in_str:
        return None
    terms.append("".join(current).strip())
    return terms


def _resolve_term(term: str, self_name: str, current: str | None) -> str | None:
    if len(term) >= 2 and term[0] == '"' and term[-1] == '"':
        return term[1:-1].replace('""', '"')
    lowered = term.lower()
    if lowered == self_name:
        return current if current is not None else ""  # an unassigned VBS variable is Empty
    if lowered in _NAMED_CONSTANTS:
        return _NAMED_CONSTANTS[lowered]
    m = _CHR_RE.fullmatch(term)
    if m:
        code = int(m.group(1))
        return chr(code) if code < 0x110000 else None
    return None


def _logical_lines(text: str) -> list[str]:
    """Joins VBS ` _` line continuations into single logical lines."""
    out, pending = [], ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith(" _") or stripped.endswith("\t_"):
            pending += stripped[:-1] + " "
            continue
        out.append(pending + line)
        pending = ""
    if pending:
        out.append(pending)
    return out


def resolve_accumulated_strings(text: str) -> dict[str, AccumulatedString]:
    """Returns every variable (keyed by lowercased name -- VBS is case-insensitive)
    whose assignments are all fully resolvable from string literals, named
    constants, `Chr(n)`, and its own previous value. A variable assigned anything
    non-literal even once is dropped, since its final value can't be known."""
    values: dict[str, AccumulatedString] = {}
    poisoned: set[str] = set()
    for line in _logical_lines(text):
        m = _ASSIGNMENT_RE.match(line)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        key = name.lower()
        if key in poisoned:
            continue
        terms = _split_concat_terms(rhs)
        prev = values.get(key)
        resolved: list[str] = []
        ok = bool(terms) and '"' in rhs
        for term in terms or []:
            part = _resolve_term(term, key, prev.value if prev else None)
            if part is None:
                ok = False
                break
            resolved.append(part)
        if not ok:
            values.pop(key, None)
            poisoned.add(key)
            continue
        fragments = (prev.fragments if prev and any(t.lower() == key for t in terms) else 0) + 1
        values[key] = AccumulatedString(name, "".join(resolved), fragments)
    return values


# ---------------------------------------------------------------------------
# Hex-pair XOR string decoder functions
# ---------------------------------------------------------------------------

_FUNCTION_RE = re.compile(
    r"^[ \t]*(?:Public\s+|Private\s+)?Function\s+([A-Za-z_]\w*)\s*\(\s*(?:ByVal\s+)?([A-Za-z_]\w*)\s*\)"
    r"(.*?)^[ \t]*End\s+Function",
    re.IGNORECASE | re.DOTALL | re.MULTILINE,
)
_KEY_VAR_RE = re.compile(r"Asc\(\s*Mid\(\s*([A-Za-z_]\w*)\s*,", re.IGNORECASE)
_MIN_PRINTABLE_RATIO = 0.9


def _find_hex_xor_decoders(text: str) -> dict[str, str]:
    """Maps decoder-function name (lowercased) -> literal XOR key, for functions
    shaped like: walk the argument two characters at a time, parse each pair as
    `CInt("&H" & pair)`, XOR it with `Asc(Mid(key, n, 1))` of a literal key
    string cycled over its length. All three markers must be present, and the key
    must be a string literal assigned inside the function body."""
    decoders = {}
    for m in _FUNCTION_RE.finditer(text):
        name, body = m.group(1), m.group(3)
        if not (re.search(r"\bXor\b", body, re.IGNORECASE)
                and re.search(r'"&H"', body, re.IGNORECASE)
                and re.search(r"\bMid\s*\(", body, re.IGNORECASE)):
            continue
        key_var = _KEY_VAR_RE.search(body)
        if not key_var:
            continue
        key_assign = re.search(rf'^\s*{re.escape(key_var.group(1))}\s*=\s*"([^"]+)"\s*$', body,
                               re.IGNORECASE | re.MULTILINE)
        if key_assign:
            decoders[name.lower()] = key_assign.group(1)
    return decoders


def _xor_hex(hex_text: str, key: str) -> str | None:
    try:
        data = bytes.fromhex(hex_text)
    except ValueError:
        return None
    key_bytes = key.encode("latin-1", errors="replace")
    decoded = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)).decode("latin-1")
    printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
    if not decoded or printable / len(decoded) < _MIN_PRINTABLE_RATIO:
        return None
    return decoded


def decode_hex_xor_strings(text: str) -> list[str]:
    """Decodes every `Decoder("<hex>")` call to a detected hex-XOR decoder function,
    in document order. Calls whose output isn't overwhelmingly printable (wrong key
    or not actually this scheme) are dropped rather than reported as garbage."""
    results = []
    for name, key in _find_hex_xor_decoders(text).items():
        for call in re.finditer(rf'\b{re.escape(name)}\s*\(\s*"([0-9A-Fa-f]{{2,}})"\s*\)', text, re.IGNORECASE):
            decoded = _xor_hex(call.group(1), key)
            if decoded is not None:
                results.append((call.start(), decoded))
    return [d for _, d in sorted(results)]


# ---------------------------------------------------------------------------
# Environment-variable staging
# ---------------------------------------------------------------------------

_ENV_SET_RE = re.compile(
    r'\.Environment\(\s*"Process"\s*\)(?:\.Item)?\(\s*"([^"]+)"\s*\)\s*=\s*([A-Za-z_]\w*)\b(?!\s*[(.&+])',
    re.IGNORECASE,
)
_CMD_CARET_RE = re.compile(r"\^(.)", re.DOTALL)
_POWERSHELL_MARKERS = (
    re.compile(r"\$[A-Za-z_]\w*\s*[-+]?="),
    re.compile(r"\bfunction\s+[A-Za-z_][\w-]*\s*[({]", re.IGNORECASE),
    re.compile(r"\[[A-Za-z]+(?:\.[A-Za-z]+)*\]::"),
    re.compile(r"\b(?:Out-Null|Get-[A-Z]\w+|Set-[A-Z]\w+|New-Object|Invoke-\w+)\b"),
)


@dataclasses.dataclass
class StagedPayload:
    env_name: str
    source_variable: str
    content: str
    fragments: int
    launcher: str | None
    looks_like_powershell: bool
    cmd_caret_unescaped: bool


def looks_like_powershell(content: str) -> bool:
    return sum(1 for r in _POWERSHELL_MARKERS if r.search(content)) >= 3


def find_env_staged_payloads(text: str, decoded_strings: list[str],
                             min_len: int = 64) -> list[StagedPayload]:
    """Finds `<shell>.Environment("Process")("NAME") = <var>` assignments -- in the
    script itself or in any decoded runtime string -- where `<var>` is a fully
    literal-resolvable string of at least `min_len` characters, and returns its
    resolved content. If a command line elsewhere consumes `%NAME%` through `cmd`
    (e.g. `cmd /c echo %NAME% | ...`), cmd's `^` escapes are undone in the
    returned content, since that's what the receiving interpreter actually sees."""
    strings = resolve_accumulated_strings(text)
    corpus = "\n".join([text, *decoded_strings])
    payloads, seen = [], set()
    for m in _ENV_SET_RE.finditer(corpus):
        env_name, var = m.group(1), m.group(2).lower()
        acc = strings.get(var)
        if acc is None or len(acc.value) < min_len or (env_name.lower(), var) in seen:
            continue
        seen.add((env_name.lower(), var))

        consume_re = re.compile(rf"\^?%{re.escape(env_name)}\^?%", re.IGNORECASE)
        launcher = next((line.strip() for line in corpus.splitlines()
                         if consume_re.search(line) and not _ENV_SET_RE.search(line)), None)
        via_cmd = bool(launcher and re.search(r"\bcmd(?:\.exe)?\b", launcher, re.IGNORECASE))
        content = _CMD_CARET_RE.sub(r"\1", acc.value) if via_cmd else acc.value

        payloads.append(StagedPayload(
            env_name=env_name, source_variable=acc.name, content=content, fragments=acc.fragments,
            launcher=launcher,
            looks_like_powershell=looks_like_powershell(content),
            cmd_caret_unescaped=via_cmd and content != acc.value,
        ))
    return payloads
