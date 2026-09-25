import base64

from vbssim_service.deobfuscate import detect_and_strip_filler, reconstruct_embedded_payload
from vbssim_service.staging import (
    decode_hex_xor_strings,
    find_env_staged_payloads,
    looks_like_powershell,
    resolve_accumulated_strings,
)

_KEY = "SyntheticKey42"


def _xor_hex(text: str, key: str = _KEY) -> str:
    return "".join(f"{ord(c) ^ ord(key[i % len(key)]):02X}" for i, c in enumerate(text))


# Same shape as the real sample's decoder (hex pairs, XOR against a literal key
# cycled over its length), with synthetic names.
_DECODER = f'''
Function DecodeIt(Blob)
    Result = ""
    KeyPos = 1
    KeyText="{_KEY}"
    For i = 1 To Len(Blob) Step 2
        Pair = Mid(Blob, i, 2)
        Num = CInt("&H" & Pair)
        KeyChar = Asc(Mid(KeyText, KeyPos, 1))
        Result = Result & Chr(Num Xor KeyChar)
        KeyPos = (KeyPos Mod Len(KeyText)) + 1
    Next
    DecodeIt = Result
End Function

Sub Runner(Code)
    Execute Code
End Sub
'''

# Inert placeholder PowerShell, split across literal fragments the way the real
# sample did it -- including cmd `^` escapes, since it's delivered via `cmd echo`.
_PS_FRAGMENTS = [
    "function Show-Placeholder ($msg) {    $counter = 0;",
    "    Write-Output $msg}$label = 'placeholder text';",
    "[System.Math]::Abs(-1) ^| Out-Null;if (^!$label) {$counter += 1};",
    "Show-Placeholder $label",
]
_EXPECTED_PS = ("function Show-Placeholder ($msg) {    $counter = 0;    Write-Output $msg}"
                "$label = 'placeholder text';[System.Math]::Abs(-1) | Out-Null;"
                "if (!$label) {$counter += 1};Show-Placeholder $label")


def _synthetic_dropper(set_line: str, run_line: str) -> str:
    body = "\n".join(f'Staged = Staged & "{frag}"' for frag in _PS_FRAGMENTS)
    return (
        "'placeholder comment\n"
        f"{body}\n"
        'Set Sh = CreateObject("WScript.Shell")\n'
        f'Runner DecodeIt("{_xor_hex(set_line)}")\n'
        f'Runner DecodeIt("{_xor_hex(run_line)}")\n'
        f"{_DECODER}"
    )


_SET_LINE = 'Sh.Environment("Process").Item("STAGEVAR") = Staged'
_RUN_LINE = 'Sh.Run("cmd.exe /v:on /c echo ^%STAGEVAR^% | !PSPATH! -", 0)'


def test_resolve_accumulated_strings_joins_self_concatenation():
    script = 'A = "one"\nA = A & "two" & vbTab & Chr(33)\nA = A & "three"'
    acc = resolve_accumulated_strings(script)["a"]
    assert acc.value == "onetwo\t!three"
    assert acc.fragments == 3


def test_resolve_accumulated_strings_handles_escaped_quotes_and_continuations():
    script = 'B = "say ""hi"" " & _\n    "there"'
    assert resolve_accumulated_strings(script)["b"].value == 'say "hi" there'


def test_resolve_accumulated_strings_drops_non_literal_variables():
    script = 'C = "start"\nC = C & SomeFunction()\nC = C & "end"'
    assert "c" not in resolve_accumulated_strings(script)


def test_decode_hex_xor_strings_recovers_statements_in_order():
    script = _synthetic_dropper(_SET_LINE, _RUN_LINE)
    assert decode_hex_xor_strings(script) == [_SET_LINE, _RUN_LINE]


def test_decode_hex_xor_strings_rejects_wrong_scheme_output():
    # Hex that wasn't produced with this key decodes to mostly-unprintable bytes.
    script = _DECODER + '\nRunner DecodeIt("' + _xor_hex("\x01" * 40) + '")\n'
    assert decode_hex_xor_strings(script) == []


def test_decode_hex_xor_strings_ignores_function_without_xor_shape():
    script = 'Function Plain(x)\n    Plain = Mid(x, 1, 2)\nEnd Function\nY = Plain("414243")'
    assert decode_hex_xor_strings(script) == []


def test_env_staged_payload_found_through_decoded_statements():
    script = _synthetic_dropper(_SET_LINE, _RUN_LINE)
    payloads = find_env_staged_payloads(script, decode_hex_xor_strings(script))
    assert len(payloads) == 1
    p = payloads[0]
    assert p.env_name == "STAGEVAR"
    assert p.source_variable == "Staged"
    assert p.fragments == len(_PS_FRAGMENTS)
    assert p.content == _EXPECTED_PS
    assert p.cmd_caret_unescaped
    assert p.looks_like_powershell
    assert "cmd.exe" in p.launcher


def test_env_staged_payload_found_when_statements_are_plain_text():
    body = "\n".join(f'Staged = Staged & "{frag}"' for frag in _PS_FRAGMENTS)
    script = f"{body}\n{_SET_LINE}\n{_RUN_LINE}\n"
    payloads = find_env_staged_payloads(script, [])
    assert [p.env_name for p in payloads] == ["STAGEVAR"]


def test_carets_kept_when_not_consumed_through_cmd():
    body = "\n".join(f'Staged = Staged & "{frag}"' for frag in _PS_FRAGMENTS)
    script = f"{body}\n{_SET_LINE}\n"
    [p] = find_env_staged_payloads(script, [])
    assert "^|" in p.content
    assert not p.cmd_caret_unescaped
    assert p.launcher is None


def test_short_env_value_not_treated_as_payload():
    script = 'Flag = "yes"\nSh.Environment("Process").Item("MYFLAG") = Flag\n'
    assert find_env_staged_payloads(script, []) == []


def test_env_set_from_non_literal_not_treated_as_payload():
    script = 'Sh.Environment("Process").Item("PATHX") = Sh.ExpandEnvironmentStrings("%WINDIR%")\n'
    assert find_env_staged_payloads(script, []) == []


def test_looks_like_powershell_requires_several_markers():
    assert looks_like_powershell(_EXPECTED_PS)
    assert not looks_like_powershell("just some ordinary sentence with a $5 price")


# ---------------------------------------------------------------------------
# A genuine Authenticode signature block is not filler
# ---------------------------------------------------------------------------

def _signature_block(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 44] for i in range(0, len(b64), 44)]
    return ("'' SIG '' Begin signature block\n"
            + "".join(f"'' SIG '' {line}\n" for line in lines)
            + "'' SIG '' End signature block\n")


# A synthetic DER prefix: SEQUENCE, then the PKCS#7 SignedData OID, then padding --
# enough structure for the detector's check, not a real signature.
_SYNTHETIC_SIGNED_DATA = bytes.fromhex("30820200" "06092a864886f70d010702" "a0") + bytes(range(256)) * 2


def test_pkcs7_signature_block_not_treated_as_filler():
    script = 'WScript.Echo "placeholder"\n' + _signature_block(_SYNTHETIC_SIGNED_DATA)
    assert detect_and_strip_filler(script, min_repeats=5).filler is None
    decoded, _ = reconstruct_embedded_payload(script, min_repeats=5)
    assert decoded is None


def test_non_signature_blob_in_signature_block_still_treated_as_filler():
    # Same layout, but the "signature" is really a hidden payload -- the
    # camouflage case the line-prefix detector exists for.
    script = 'WScript.Echo "placeholder"\n' + _signature_block(b"hidden synthetic payload bytes. " * 12)
    assert detect_and_strip_filler(script, min_repeats=5).filler == "'' SIG '' "


def test_long_hex_run_not_decoded_as_base64():
    script = f'X = DecodeIt("{"3B5457" * 80}")\n'
    decoded, _ = reconstruct_embedded_payload(script, min_repeats=50)
    assert decoded is None
