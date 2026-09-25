"""VBSSim: statically detects and undoes three real, observed VBScript
junk-filler obfuscation techniques -- interspersing every character of an
embedded base64 payload with a long junk filler; splicing a short marker token
into otherwise-plaintext/hex string fragments passed to a custom "decode"
function; and splitting a base64 blob across many lines each prefixed with a
repeated marker (mimicking a real PowerShell/Authenticode "signature block") --
reconstructs and extracts the hidden payload, and recognizes (without ever
performing) dangerous WSH/PowerShell idioms: hidden-window process creation
(WMI/WScript.Shell), reflective .NET assembly loading, VBScript's own
dynamic-code-execution builtins, scheduled-task persistence, and a fake/
inapplicable digital-signature block used as camouflage. Also decodes calls to a
hex-pair XOR string-decoder function and recovers a script payload assembled from
literal string fragments and handed to another interpreter through a process
environment variable (e.g. `cmd /c echo %VAR% | powershell -`).

No VBScript interpreter is ever invoked, no `Execute`/`Eval`/`ExecuteGlobal` is ever
called on script content, and no subprocess is ever spawned by this service --
purely regex/string-based static analysis, mirroring the sibling BashSim/PhpSim
services' approach for their respective languages.
"""
from __future__ import annotations

import json
import os

from assemblyline.common.identify import Identify
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultKeyValueSection, ResultSection

from vbssim_service.deobfuscate import reconstruct_embedded_payload
from vbssim_service.scanner import extract_powershell_invoke_literals, scan
from vbssim_service.staging import decode_hex_xor_strings, find_env_staged_payloads

_KIND_TO_HEURISTIC = {
    "wmi_hidden_process": (3, "T1047"),
    "reflective_dotnet_load": (4, "T1620"),
    "vbs_dynamic_exec": (5, "T1059.005"),
    "fake_signature_block": (8, "T1036.001"),
}


def _decode_text(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe") or raw.count(b"\x00") > len(raw) // 3:
        return raw.decode("utf-16-le", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def _classify_signature(sniffed_type: str) -> str:
    if sniffed_type.startswith("executable"):
        return "executable"
    if sniffed_type.startswith(("code/", "text/")):
        return "script_or_text"
    return "other"


class VBSSim(ServiceBase):
    def __init__(self, config=None) -> None:
        super().__init__(config)
        self.identify = None

    def start(self) -> None:
        self.identify = Identify(use_cache=False)

    def execute(self, request: ServiceRequest) -> None:
        text = _decode_text(request.file_contents)
        result = Result()

        min_repeats = request.get_param("min_filler_repeats")
        decoded, filler_result = reconstruct_embedded_payload(text, min_repeats=min_repeats)

        audit_log = {
            "filler_detected": filler_result.filler,
            "filler_occurrences": filler_result.occurrences,
            "decoded_payload_size": len(decoded) if decoded else 0,
        }

        if filler_result.filler:
            filler_section = ResultSection(
                "Junk-character obfuscation detected and stripped",
                body=f"A {len(filler_result.filler)}-character junk filler was found interspersed "
                     f"{filler_result.occurrences} times throughout the script, padding what is "
                     "likely a hidden base64-encoded payload to defeat naive string/YARA extraction. "
                     "The filler has been stripped for analysis below.",
            )
            filler_section.set_heuristic(1, signature="junk_filler_obfuscation")
            result.add_section(filler_section)

        # Scan the de-fillered text, not the raw text -- on a real sample the junk
        # filler is interspersed through the *entire* file, not just the base64
        # payload blob, so a reflective-invoke literal like `[Foo.Bar]::Baz("...")`
        # is itself filler-obfuscated and never matches against raw `text`.
        # detect_and_strip_filler() returns the original text unchanged when no
        # filler is detected, so this is always safe to use.
        clean_text = filler_result.cleaned_text

        # temp_submission_data must be set BEFORE add_extracted() -- it propagates to
        # the *subsequent tasks resulting from* adding an extracted file, so setting
        # it after the child task was already created misses the child entirely.
        # (Real bug found this session: DotnetConfigDecryptor never saw these
        # literals on a live submission because this was originally ordered the
        # other way around.)
        invoke_literals = extract_powershell_invoke_literals(clean_text)
        candidate_ciphertexts = sorted({
            literal for inv in invoke_literals for literal in inv["candidate_literals"]
        })
        if candidate_ciphertexts:
            request.temp_submission_data["vbssim_candidate_ciphertexts"] = candidate_ciphertexts

        # Hex-XOR decoded strings are typically what the script later `Execute`s --
        # the statements that stage and launch a payload may exist only there.
        decoded_strings = decode_hex_xor_strings(clean_text)
        if decoded_strings:
            audit_log["hex_xor_decoded_strings"] = decoded_strings
            xor_section = ResultSection(
                "Hex/XOR-encoded strings decoded",
                body="\n".join(decoded_strings[:50]),
            )
            xor_section.set_heuristic(10, signature="hex_xor_strings")
            result.add_section(xor_section)

        staged = find_env_staged_payloads(clean_text, decoded_strings)
        for i, payload in enumerate(staged):
            ext = "ps1" if payload.looks_like_powershell else "txt"
            name = f"{payload.env_name}_env_payload.{ext}"
            out_path = os.path.join(self.working_directory, f"staged_{i}_{name}")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(payload.content)
            added = request.add_extracted(
                out_path, name,
                f"Script assembled in variable {payload.source_variable} and staged through "
                f"environment variable {payload.env_name}",
            )
            if not added:
                continue
            staged_section = ResultKeyValueSection("Script payload staged through a process environment variable")
            staged_section.set_item("environment_variable", payload.env_name)
            staged_section.set_item("source_variable", payload.source_variable)
            staged_section.set_item("literal_fragments", payload.fragments)
            staged_section.set_item("size", len(payload.content))
            staged_section.set_item("launcher", payload.launcher or "(not found)")
            staged_section.set_item("cmd_caret_escapes_removed", payload.cmd_caret_unescaped)
            staged_section.set_heuristic(9, signature="powershell" if payload.looks_like_powershell else "other_script")
            result.add_section(staged_section)
            audit_log.setdefault("env_staged_payloads", []).append({
                "environment_variable": payload.env_name, "source_variable": payload.source_variable,
                "size": len(payload.content), "launcher": payload.launcher, "extracted_as": name,
            })

        if decoded:
            out_path = os.path.join(self.working_directory, f"{request.sha256}_reconstructed.bin")
            with open(out_path, "wb") as f:
                f.write(decoded)
            file_info = self.identify.fileinfo(out_path, skip_fuzzy_hashes=True, calculate_entropy=False)
            sniffed_type = file_info["type"]

            added = request.add_extracted(
                out_path, f"{request.sha256}_reconstructed.bin",
                "Payload reconstructed from an obfuscated/split base64 blob embedded in this script",
            )
            if added:
                payload_section = ResultKeyValueSection("Embedded payload reconstructed")
                payload_section.set_item("size", len(decoded))
                payload_section.set_item("sniffed_type", sniffed_type)
                payload_section.set_item("sha256", file_info.get("sha256"))
                payload_section.set_heuristic(2, signature=_classify_signature(sniffed_type))
                result.add_section(payload_section)
                audit_log["decoded_payload_sniffed_type"] = sniffed_type

        findings = scan("\n".join([clean_text, *decoded_strings]))
        by_kind: dict[str, list] = {}
        for finding in findings:
            by_kind.setdefault(finding.kind, []).append(finding)

        titles = {
            "wmi_hidden_process": "WMI hidden-window process creation recognized (not performed)",
            "reflective_dotnet_load": "Reflective .NET assembly load recognized (not performed)",
            "vbs_dynamic_exec": "VBScript dynamic code execution recognized (not performed)",
            "fake_signature_block": "Fake/inapplicable digital-signature block detected",
        }
        for kind, items in by_kind.items():
            if kind not in _KIND_TO_HEURISTIC:
                continue
            heur_id, attack_id = _KIND_TO_HEURISTIC[kind]
            section = ResultSection(titles[kind], body="\n".join(f.snippet for f in items[:20]))
            section.set_heuristic(heur_id, signature=kind)
            result.add_section(section)

        scheduled = [f for f in findings if f.kind == "scheduled_task_persistence"]
        if scheduled:
            boot_trigger = any(f.detail.get("boot_trigger") for f in scheduled)
            sched_section = ResultSection(
                "Scheduled-task persistence recognized (not performed)",
                body="\n".join(f.snippet for f in scheduled[:20])
                + ("\n\n(Registers a BootTrigger -- survives reboots.)" if boot_trigger else ""),
            )
            sched_section.set_heuristic(6, signature="boot_persistent" if boot_trigger else "scheduled_task")
            result.add_section(sched_section)

        if candidate_ciphertexts:
            lit_section = ResultSection(
                "Candidate encrypted literal(s) passed to a reflective invocation",
                body=f"{len(candidate_ciphertexts)} long base64-shaped literal argument(s) were found "
                     "passed into a `[Namespace.Class]::Method(...)` static invocation -- often how a "
                     "reflectively-loaded payload's own encrypted config is supplied, since it may never "
                     "appear as a string constant in the loaded assembly itself. Stored in "
                     "temp_submission_data for a sibling service to attempt decryption against.",
            )
            lit_section.set_heuristic(7, signature="candidate_ciphertext_literals")
            result.add_section(lit_section)
            audit_log["candidate_ciphertexts"] = candidate_ciphertexts

        log_path = os.path.join(self.working_directory, "vbssim_findings_log.json")
        with open(log_path, "w") as f:
            json.dump(audit_log, f, indent=2)
        request.add_supplementary(log_path, "vbssim_findings_log.json", "Full VBSSim de-obfuscation/scan audit log")

        request.result = result
