"""Regex patterns for VBSSim's static scanner. Grounded in a real observed sample:
a heavily obfuscated VBS dropper that reflectively loaded a .NET payload via
PowerShell, hid its own execution behind WMI/WScript.Shell with a hidden window,
and registered boot-persistent scheduled-task re-infection.
"""
import re

# WMI-based hidden process creation: Win32_Process.Create with a ShowWindow=0
# (hidden) startup object *in the same match window*, not just anywhere in the
# file -- WMI process creation and setting some unrelated window's visibility are
# both individually common in legitimate admin/IT scripts, so requiring them to
# actually co-occur (not just both appear somewhere in a large file) is what makes
# this a meaningful signal rather than the same false-positive-prone "two common
# things happen to both exist in this file" pattern already found and fixed in
# PhpSim's privilege_escalation check this session.
RE_WMI_HIDDEN_PROCESS = re.compile(
    # \.Create\b, not \.Create\(: VBScript can call a method with or without
    # parentheses (`obj.Create "x", Null, y` is valid, common Sub-call syntax) --
    # requiring parens missed exactly this shape in this pattern's own test case.
    r"(?:Win32_Process.{0,400}?\.Create\b.{0,200}?ShowWindow\s*=\s*0\b"
    r"|ShowWindow\s*=\s*0\b.{0,200}?Win32_Process.{0,400}?\.Create\b)",
    re.IGNORECASE | re.DOTALL,
)

# Reflective .NET assembly loading from a PowerShell command line embedded in the
# VBS -- the exact technique used to run a payload without ever writing it to disk.
RE_REFLECTIVE_DOTNET_LOAD = re.compile(
    r"\[AppDomain\]::CurrentDomain\.Load\(|\[Reflection\.Assembly\]::Load\(",
    re.IGNORECASE,
)
# VBScript's own dynamic-code-execution builtins -- the direct analog of PhpSim's
# eval/assert detection and BashSim's direct_execution detection. Only fires when
# the argument is NOT a bare quoted string literal (Execute("MsgBox 1") is inert
# and common in benign/example code; Execute(someVariable) -- operating on
# something built/decoded at runtime -- is the actually-notable shape).
RE_VBS_DYNAMIC_EXEC = re.compile(r"\b(?:Execute|ExecuteGlobal|Eval|GetRef)\s*\(\s*(?!\s*\")", re.IGNORECASE)

# Scheduled-task persistence, scored ONLY when corroborated by a hidden-window or
# boot-triggered signal nearby -- scheduled-task creation alone is what nearly
# every legitimate software installer does, so the bare API call alone is not a
# meaningful signal (same class of fix as PhpSim's privilege_escalation this
# session: two independently-common things must actually co-occur to mean
# something).
RE_SCHEDULED_TASK_PERSISTENCE = re.compile(
    r'CreateObject\(\s*"Schedule\.Service"\s*\)|RegisterTaskDefinition\(|New-ScheduledTask\b|Register-ScheduledTask\b',
    re.IGNORECASE,
)
RE_BOOT_TRIGGER = re.compile(r"\bBootTrigger\b", re.IGNORECASE)
RE_HIDDEN_WINDOW_STYLE = re.compile(r"WindowStyle\s+Hidden\b|ShowWindow\s*=\s*0\b", re.IGNORECASE)

# A `[Namespace.Class]::Method(...)` PowerShell static-method invocation with at
# least one long, base64-shaped quoted literal argument -- exactly the shape a
# reflectively-loaded .NET payload's own encrypted config gets passed in as, since
# it never appears as a string constant inside the .NET assembly itself. Captures
# the whole argument list so candidate literals can be pulled out of it.
RE_POWERSHELL_STATIC_INVOKE = re.compile(
    r"\[([A-Za-z0-9_.]+)\]::([A-Za-z0-9_]+)\(([^)]*)\)"
)
RE_QUOTED_LONG_BASE64_LITERAL = re.compile(r"'([A-Za-z0-9+/=]{40,})'")

# A PowerShell-style Authenticode "signature block" (the trailing comment format
# Set-AuthenticodeSignature writes into a *.ps1*, normally "# SIG # Begin/End
# signature block") -- confirmed on a real sample: this exact marker text (using
# VBS's `''` comment prefix instead of PowerShell's `#`) was pasted into a *.vbs*
# file, which has no such convention and never verifies or even parses it. VBS
# doesn't support script signing at all, so its mere presence in a code/vbs file
# is itself the signal -- it exists purely to make the file look digitally signed
# to a human skimming it or a naive automated trust check, not because anything
# will ever validate it.
RE_FAKE_SIGNATURE_BLOCK_BEGIN = re.compile(r"Begin signature block", re.IGNORECASE)
RE_FAKE_SIGNATURE_BLOCK_END = re.compile(r"End signature block", re.IGNORECASE)
