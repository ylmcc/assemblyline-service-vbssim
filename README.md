# VBSSim

Docker Hub: [kylemc54321/assemblyline-service-vbssim](https://hub.docker.com/r/kylemc54321/assemblyline-service-vbssim)

An AssemblyLine v4 service that statically detects and undoes a real, observed
VBScript obfuscation technique — interspersing every real character of an embedded
base64 payload with a long junk filler, to defeat naive `strings`/YARA extraction —
reconstructs and extracts the hidden payload, and recognizes (without ever
performing) dangerous WSH/PowerShell idioms: hidden-window WMI process creation,
reflective .NET assembly loading, VBScript's own dynamic-code-execution builtins,
and corroborated scheduled-task persistence.

This mirrors the sibling `BashSim`/`PhpSim` services' approach for their respective
languages: pure regex/string-based static analysis, **no VBScript interpreter is
ever invoked**, no `Execute`/`Eval`/`ExecuteGlobal` is ever called on script content.

## Why this exists

A real 18MB, 10,000+-line VBS dropper was found where every single base64 character
of an embedded ~400KB .NET payload was followed by the same ~15-character junk
Unicode filler — a technique specifically designed to defeat naive string/YARA
extraction by diluting any recognizable byte sequence. No existing service in this
collection recovered the embedded payload automatically; doing so required manual,
by-hand analysis. This service automates that recovery.

## Detected signals

| Heuristic | Meaning |
|---|---|
| 1. Junk-character obfuscation detected | A highly-repeated, deliberately unusual filler was found and stripped. |
| 2. Embedded payload reconstructed | A payload was decoded from the (de-junked) base64 blob and extracted for further analysis. |
| 3. WMI hidden-window process creation | `Win32_Process.Create` with `ShowWindow = 0` in the same statement — not just both appearing somewhere in the file. |
| 4. Reflective .NET assembly load | `[AppDomain]::CurrentDomain.Load(...)` — loads a .NET payload directly into memory, never touching disk. |
| 5. VBScript dynamic code execution | `Execute`/`ExecuteGlobal`/`Eval` on a dynamically-built variable, not a bare literal. |
| 6. Corroborated scheduled-task persistence | Scheduled-task creation *alongside* a hidden-window or boot-triggered signal — not scheduled-task creation alone, which is what ordinary installers do constantly. |
| 7. Candidate encrypted literal(s) for cross-service use | Long base64-shaped literals passed into a `[Namespace.Class]::Method(...)` reflective invocation, stashed in `temp_submission_data` for a sibling service (e.g. a future generic .NET config decryptor) to attempt decryption against. |

## A deliberate design choice: avoiding false-positive-prone single signals

Every heuristic here was tightened at least once before shipping, specifically to
avoid the "two independently-common things both happen to appear somewhere in this
file" false-positive pattern (the same class of bug found and fixed in the sibling
Magpie and PhpSim services this session):

- WMI hidden-process detection requires `ShowWindow = 0` in the *same* match window
  as the `Win32_Process.Create` call, not just present anywhere in the file.
- Scheduled-task creation alone is **not** scored — it's what practically every
  software installer does. Only corroborated (by a boot trigger or hidden window
  style) does it fire.
- `Execute`/`Eval` on a bare string literal is not flagged — only on what looks like
  a dynamically-built variable.
- The junk-filler detector requires the candidate filler to be long (≥ 8 chars) or
  contain a non-ASCII/control character, specifically to avoid misfiring on ordinary
  code's own repetitive formatting (e.g. consistent indentation between short,
  coincidentally base64-alphabet-shaped variable names).

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install assemblyline-v4-service assemblyline-service-utilities pytest pyyaml
.venv/bin/pytest test/
```

No test in this repo uses real malware or a real obfuscation filler string — the
synthetic fixtures use an obviously-placeholder Unicode filler and a synthetic
embedded "payload" (plain text, not an executable), shaped the same way as the real
technique this service was built to recover from.
