"""VBSSim: statically detects and undoes a real, observed VBScript obfuscation
technique (interspersing every real character of an embedded base64 payload with a
long junk filler, to defeat naive string/YARA extraction), reconstructs and
extracts the hidden payload, and recognizes (without ever performing) dangerous
WSH/PowerShell idioms: hidden-window process creation (WMI/WScript.Shell),
reflective .NET assembly loading, VBScript's own dynamic-code-execution builtins,
and scheduled-task persistence.

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

_KIND_TO_HEURISTIC = {
    "wmi_hidden_process": (3, "T1047"),
    "reflective_dotnet_load": (4, "T1620"),
    "vbs_dynamic_exec": (5, "T1059.005"),
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

        findings = scan(text)
        by_kind: dict[str, list] = {}
        for finding in findings:
            by_kind.setdefault(finding.kind, []).append(finding)

        titles = {
            "wmi_hidden_process": "WMI hidden-window process creation recognized (not performed)",
            "reflective_dotnet_load": "Reflective .NET assembly load recognized (not performed)",
            "vbs_dynamic_exec": "VBScript dynamic code execution recognized (not performed)",
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

        invoke_literals = extract_powershell_invoke_literals(text)
        candidate_ciphertexts = sorted({
            literal for inv in invoke_literals for literal in inv["candidate_literals"]
        })
        if candidate_ciphertexts:
            request.temp_submission_data["vbssim_candidate_ciphertexts"] = candidate_ciphertexts
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
