"""Pure regex-based recognition of dangerous VBS/WSH idioms -- never executes,
parses, or interprets anything, purely pattern matching over the script's own text.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import patterns as p


@dataclass
class Finding:
    kind: str
    detail: dict = field(default_factory=dict)
    snippet: str = ""


def _snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    return text[max(0, start - pad):min(len(text), end + pad)].strip()


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for m in p.RE_WMI_HIDDEN_PROCESS.finditer(text):
        findings.append(Finding("wmi_hidden_process", {}, _snippet(text, m.start(), m.end())))

    for m in p.RE_REFLECTIVE_DOTNET_LOAD.finditer(text):
        findings.append(Finding("reflective_dotnet_load", {}, _snippet(text, m.start(), m.end())))

    for m in p.RE_VBS_DYNAMIC_EXEC.finditer(text):
        findings.append(Finding("vbs_dynamic_exec", {"builtin": m.group(0).rstrip("(").strip()},
                                 _snippet(text, m.start(), m.end())))

    # Scheduled-task creation alone is what nearly every legitimate installer does --
    # only report it when corroborated by an actual hidden-window or boot-triggered
    # signal nearby, which is what distinguishes a re-infection/persistence
    # mechanism from an ordinary installer registering a normal maintenance task.
    task_match = p.RE_SCHEDULED_TASK_PERSISTENCE.search(text)
    if task_match:
        boot_trigger = bool(p.RE_BOOT_TRIGGER.search(text))
        hidden_window = bool(p.RE_HIDDEN_WINDOW_STYLE.search(text))
        if boot_trigger or hidden_window:
            findings.append(Finding(
                "scheduled_task_persistence", {"boot_trigger": boot_trigger, "hidden_window": hidden_window},
                _snippet(text, task_match.start(), task_match.end()),
            ))

    begin_match = p.RE_FAKE_SIGNATURE_BLOCK_BEGIN.search(text)
    if begin_match and p.RE_FAKE_SIGNATURE_BLOCK_END.search(text):
        findings.append(Finding(
            "fake_signature_block", {},
            _snippet(text, begin_match.start(), begin_match.end()),
        ))

    return findings


def extract_powershell_invoke_literals(text: str) -> list[dict]:
    """Finds `[Namespace.Class]::Method('<literal>', ...)`-shaped static-method
    invocations and pulls out any long, base64-shaped quoted literal arguments --
    this is where a reflectively-loaded .NET payload's own encrypted config gets
    passed in when it never appears as a string constant in the assembly itself
    (confirmed on a real sample: the actual C2 URL only existed as a literal here,
    not anywhere in the loaded .NET assembly's own metadata)."""
    results = []
    for m in p.RE_POWERSHELL_STATIC_INVOKE.finditer(text):
        namespace_class, method, arglist = m.group(1), m.group(2), m.group(3)
        literals = p.RE_QUOTED_LONG_BASE64_LITERAL.findall(arglist)
        if literals:
            results.append({
                "class": namespace_class, "method": method,
                "candidate_literals": literals,
            })
    return results
