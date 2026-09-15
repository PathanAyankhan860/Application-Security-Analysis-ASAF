"""
ASAF / MobSF - Static PE/EXE Analyzer

This module performs static analysis of Windows PE files (.exe/.dll).
It NEVER executes the analyzed file.

Requires:
    pefile

Output:
    A JSON-serializable dictionary containing:
      - file metadata
      - hashes
      - PE headers
      - sections
      - imports
      - exports
      - strings
      - URLs/domains/IPs
      - PowerShell/CMD/registry indicators
      - security mitigations
      - TLS callbacks
      - overlay information
      - resources
      - suspicious sections
      - packer/obfuscation heuristics
      - findings
      - score
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
from collections import Counter
from typing import Any, Dict, List, Optional

import pefile


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_IMPORTS = {
    # Process / execution
    "CreateProcessA",
    "CreateProcessW",
    "CreateProcessAsUserA",
    "CreateProcessAsUserW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "ShellExecuteExW",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "OpenProcess",
    "TerminateProcess",

    # Memory
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "MapViewOfFile",
    "CreateFileMappingA",
    "CreateFileMappingW",

    # DLL loading
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",

    # Injection / native execution
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "SetThreadContext",
    "ResumeThread",

    # Credential / token
    "OpenThreadToken",
    "OpenProcessToken",
    "DuplicateToken",
    "DuplicateTokenEx",
    "AdjustTokenPrivileges",
    "ImpersonateLoggedOnUser",

    # Services
    "OpenSCManagerA",
    "OpenSCManagerW",
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
    "ControlService",
    "DeleteService",

    # Registry
    "RegOpenKeyA",
    "RegOpenKeyW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegCreateKeyA",
    "RegCreateKeyW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegSetValueA",
    "RegSetValueW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegDeleteValueA",
    "RegDeleteValueW",

    # File manipulation
    "CreateFileA",
    "CreateFileW",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "CopyFileA",
    "CopyFileW",
    "WriteFile",

    # Networking
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReadData",
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",

    # Anti-analysis
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtQueryInformationProcess",
    "GetTickCount",
    "QueryPerformanceCounter",

    # Cryptography / encoding
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContextA",
    "CryptAcquireContextW",

    # Command execution
    "system",
    "popen",
    "_popen",
    "WinExec",
}


SUSPICIOUS_STRINGS = {
    "powershell",
    "powershell.exe",
    "-encodedcommand",
    "-enc",
    "invoke-expression",
    "iex ",
    "invoke-webrequest",
    "downloadstring",
    "downloadfile",
    "cmd.exe",
    "cmd /c",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "schtasks",
    "wmic",
    "vssadmin",
    "bcdedit",
    "net user",
    "net localgroup",
    "whoami",
    "mimikatz",
    "lsass",
    "sam\\",
    "security\\",
    "currentversion\\run",
    "currentversion\\runonce",
    "appdata",
    "temp\\",
    "startup",
}


PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".upx",
    "aspack",
    ".aspack",
    "mpress1",
    "mpress2",
    ".packed",
    "pec",
    "petite",
    "themida",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".enigma1",
    ".enigma2",
}


COMMON_SECTION_NAMES = {
    ".text",
    ".data",
    ".rdata",
    ".pdata",
    ".rsrc",
    ".reloc",
    ".idata",
    ".edata",
    ".bss",
    ".tls",
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _safe_decode(value: Any) -> str:
    """Safely decode PE byte strings."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode(
            "utf-8",
            errors="replace",
        )

    return str(value)


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def _hash_file(path: str) -> Dict[str, str]:
    """Calculate MD5/SHA1/SHA256/SHA512."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


def _read_strings(path: str, minimum_length: int = 5) -> Dict[str, Any]:
    """
    Extract ASCII and UTF-16LE strings.

    This is static extraction only.
    """

    with open(path, "rb") as handle:
        data = handle.read()

    ascii_pattern = rb"[\x20-\x7e]{%d,}" % minimum_length
    unicode_pattern = (
        rb"(?:[\x20-\x7e]\x00){%d,}"
        % minimum_length
    )

    ascii_strings = [
        match.decode("ascii", errors="replace")
        for match in re.findall(ascii_pattern, data)
    ]

    unicode_strings = [
        match.decode("utf-16le", errors="replace")
        for match in re.findall(unicode_pattern, data)
    ]

    all_strings = ascii_strings + unicode_strings

    # Remove duplicates while preserving order.
    unique = list(dict.fromkeys(all_strings))

    return {
        "count": len(unique),
        "ascii_count": len(ascii_strings),
        "unicode_count": len(unicode_strings),
        "strings": unique[:10000],
    }


def _find_network_indicators(strings: List[str]) -> Dict[str, List[str]]:
    """Extract URLs, domains and IPv4 addresses."""

    urls = set()
    domains = set()
    ips = set()

    url_pattern = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE,
    )

    ip_pattern = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|io|biz|info|ru|cn|uk|de|xyz|top|site|online|"
        r"cloud|app|dev|co|me|tv|pro|live)\b",
        re.IGNORECASE,
    )

    for value in strings:
        for match in url_pattern.findall(value):
            urls.add(match.rstrip(".,;"))

        for match in ip_pattern.findall(value):
            parts = match.split(".")

            if all(0 <= int(part) <= 255 for part in parts):
                ips.add(match)

        for match in domain_pattern.findall(value):
            domains.add(match.lower())

    return {
        "urls": sorted(urls)[:1000],
        "domains": sorted(domains)[:1000],
        "ips": sorted(ips)[:1000],
    }


def _find_string_indicators(strings: List[str]) -> List[Dict[str, str]]:
    """Find command, PowerShell, registry and other indicators."""

    findings = []

    for value in strings:
        lowered = value.lower()

        for indicator in SUSPICIOUS_STRINGS:
            if indicator in lowered:
                category = "SUSPICIOUS_STRING"

                if "powershell" in indicator or indicator in {
                    "-enc",
                    "-encodedcommand",
                    "invoke-expression",
                    "invoke-webrequest",
                    "downloadstring",
                    "downloadfile",
                }:
                    category = "POWERSHELL"

                elif "cmd" in indicator:
                    category = "COMMAND_EXECUTION"

                elif "currentversion\\run" in indicator:
                    category = "PERSISTENCE"

                elif "reg" in indicator:
                    category = "REGISTRY"

                findings.append(
                    {
                        "category": category,
                        "indicator": indicator,
                        "value": value[:500],
                    }
                )

                break

    return findings[:1000]


# ---------------------------------------------------------------------------
# PE headers
# ---------------------------------------------------------------------------

def _analyze_headers(pe: pefile.PE) -> Dict[str, Any]:
    """Analyze DOS, COFF and optional PE headers."""

    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER

    machine = int(file_header.Machine)

    machine_names = {
        0x014C: "x86",
        0x8664: "x64",
        0x01C0: "ARM",
        0x01C4: "ARM Thumb-2",
        0xAA64: "ARM64",
    }

    subsystem_names = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows CUI / Console",
        5: "OS/2 CUI",
        7: "POSIX CUI",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        13: "EFI ROM",
        14: "Xbox",
        16: "Windows Boot Application",
    }

    magic = int(optional.Magic)

    if magic == 0x10B:
        pe_format = "PE32"
    elif magic == 0x20B:
        pe_format = "PE32+"
    else:
        pe_format = "Unknown"

    return {
        "machine": machine,
        "architecture": machine_names.get(
            machine,
            "Unknown",
        ),
        "format": pe_format,
        "timestamp": int(file_header.TimeDateStamp),
        "number_of_sections": int(
            file_header.NumberOfSections
        ),
        "characteristics": int(
            file_header.Characteristics
        ),
        "entry_point": hex(
            int(optional.AddressOfEntryPoint)
        ),
        "image_base": hex(
            int(optional.ImageBase)
        ),
        "image_base_decimal": int(optional.ImageBase),
        "section_alignment": int(
            optional.SectionAlignment
        ),
        "file_alignment": int(
            optional.FileAlignment
        ),
        "image_size": int(
            optional.SizeOfImage
        ),
        "headers_size": int(
            optional.SizeOfHeaders
        ),
        "subsystem": int(optional.Subsystem),
        "subsystem_name": subsystem_names.get(
            int(optional.Subsystem),
            "Unknown",
        ),
        "dll_characteristics": int(
            optional.DllCharacteristics
        ),
    }


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _analyze_sections(pe: pefile.PE) -> Dict[str, Any]:
    """Analyze PE sections and entropy."""

    sections = []
    suspicious_sections = []

    for section in pe.sections:
        name = _safe_decode(section.Name)

        characteristics = int(section.Characteristics)

        readable = bool(
            characteristics & 0x40000000
        )

        writable = bool(
            characteristics & 0x80000000
        )

        executable = bool(
            characteristics & 0x20000000
        )

        entropy = section.get_entropy()

        section_data = section.get_data()

        info = {
            "name": name,
            "virtual_address": hex(
                int(section.VirtualAddress)
            ),
            "virtual_size": int(
                section.Misc_VirtualSize
            ),
            "raw_size": int(
                section.SizeOfRawData
            ),
            "raw_offset": hex(
                int(section.PointerToRawData)
            ),
            "entropy": round(entropy, 4),
            "characteristics": hex(characteristics),
            "readable": readable,
            "writable": writable,
            "executable": executable,
            "sha256": hashlib.sha256(
                section_data
            ).hexdigest(),
        }

        sections.append(info)

        lowered_name = name.lower().strip("\x00")

        reasons = []

        if lowered_name in PACKER_SECTION_NAMES:
            reasons.append("Known packer-like section name")

        if entropy >= 7.2:
            reasons.append(
                "Very high section entropy"
            )

        if executable and writable:
            reasons.append(
                "Executable and writable section"
            )

        if not name.strip("\x00"):
            reasons.append(
                "Unnamed PE section"
            )

        if reasons:
            suspicious_sections.append(
                {
                    "name": name,
                    "reasons": reasons,
                }
            )

    return {
        "count": len(sections),
        "sections": sections,
        "suspicious_sections": suspicious_sections,
    }


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

def _analyze_imports(pe: pefile.PE) -> Dict[str, Any]:
    """Analyze imported DLLs and functions."""

    libraries = []
    suspicious = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return {
            "library_count": 0,
            "function_count": 0,
            "libraries": [],
            "suspicious_imports": [],
        }

    function_count = 0

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = _safe_decode(entry.dll)

        functions = []

        for imported in entry.imports:
            function_name = ""

            if imported.name:
                function_name = _safe_decode(
                    imported.name
                )
            else:
                function_name = (
                    f"ordinal:{imported.ordinal}"
                )

            functions.append(function_name)
            function_count += 1

            if function_name in SUSPICIOUS_IMPORTS:
                suspicious.append(
                    {
                        "dll": dll,
                        "function": function_name,
                    }
                )

        libraries.append(
            {
                "dll": dll,
                "function_count": len(functions),
                "functions": functions[:2000],
            }
        )

    return {
        "library_count": len(libraries),
        "function_count": function_count,
        "libraries": libraries,
        "suspicious_imports": suspicious,
    }


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

def _analyze_exports(pe: pefile.PE) -> Dict[str, Any]:
    """Analyze PE exports."""

    exports = []

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return {
            "count": 0,
            "exports": [],
        }

    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = ""

        if symbol.name:
            name = _safe_decode(symbol.name)

        exports.append(
            {
                "name": name,
                "ordinal": int(symbol.ordinal),
                "address": hex(int(symbol.address)),
            }
        )

    return {
        "count": len(exports),
        "exports": exports[:5000],
    }


# ---------------------------------------------------------------------------
# Security mitigations
# ---------------------------------------------------------------------------

def _analyze_mitigations(pe: pefile.PE) -> Dict[str, Any]:
    """
    Analyze ASLR, DEP/NX and CFG flags.
    """

    characteristics = int(
        pe.OPTIONAL_HEADER.DllCharacteristics
    )

    dynamic_base = bool(
        characteristics & 0x0040
    )

    nx_compat = bool(
        characteristics & 0x0100
    )

    guard_cf = bool(
        characteristics & 0x4000
    )

    high_entropy_va = bool(
        characteristics & 0x0020
    )

    force_integrity = bool(
        characteristics & 0x0080
    )

    return {
        "aslr": dynamic_base,
        "dep_nx": nx_compat,
        "cfg": guard_cf,
        "high_entropy_va": high_entropy_va,
        "force_integrity": force_integrity,
        "dll_characteristics": hex(characteristics),
    }


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def _analyze_tls(pe: pefile.PE) -> Dict[str, Any]:
    """Detect TLS callbacks."""

    result = {
        "present": False,
        "callback_count": 0,
        "callbacks": [],
    }

    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return result

    result["present"] = True

    tls = pe.DIRECTORY_ENTRY_TLS.struct

    callback_va = int(
        tls.AddressOfCallBacks
    )

    if callback_va == 0:
        return result

    try:
        image_base = int(
            pe.OPTIONAL_HEADER.ImageBase
        )

        callback_rva = callback_va - image_base

        if callback_rva < 0:
            return result

        offset = pe.get_offset_from_rva(
            callback_rva
        )

        pointer_size = (
            8
            if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
            else 4
        )

        callbacks = []

        while True:
            data = pe.__data__[offset:offset + pointer_size]

            if len(data) != pointer_size:
                break

            if pointer_size == 8:
                address = struct.unpack(
                    "<Q",
                    data,
                )[0]
            else:
                address = struct.unpack(
                    "<I",
                    data,
                )[0]

            if address == 0:
                break

            callbacks.append(hex(address))

            offset += pointer_size

            if len(callbacks) >= 100:
                break

        result["callbacks"] = callbacks
        result["callback_count"] = len(callbacks)

    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Overlay
# ---------------------------------------------------------------------------

def _analyze_overlay(pe: pefile.PE, path: str) -> Dict[str, Any]:
    """Detect data appended after the final PE section."""

    result = {
        "present": False,
        "size": 0,
        "offset": None,
        "sha256": None,
    }

    try:
        overlay_offset = pe.get_overlay_data_start_offset()

        if overlay_offset is None:
            return result

        file_size = os.path.getsize(path)

        if overlay_offset >= file_size:
            return result

        size = file_size - overlay_offset

        result["present"] = size > 0
        result["size"] = size
        result["offset"] = overlay_offset

        with open(path, "rb") as handle:
            handle.seek(overlay_offset)
            overlay = handle.read()

        result["sha256"] = hashlib.sha256(
            overlay
        ).hexdigest()

    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Resources / manifest
# ---------------------------------------------------------------------------

def _analyze_resources(pe: pefile.PE) -> Dict[str, Any]:
    """Analyze resource presence and basic resource types."""

    result = {
        "present": False,
        "resource_count": 0,
        "types": [],
        "manifest_present": False,
    }

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return result

    result["present"] = True

    type_names = []

    resource_type_map = {
        1: "CURSOR",
        2: "BITMAP",
        3: "ICON",
        4: "MENU",
        5: "DIALOG",
        6: "STRING",
        9: "ACCELERATOR",
        10: "RCDATA",
        11: "MESSAGETABLE",
        12: "GROUP_CURSOR",
        14: "GROUP_ICON",
        16: "VERSION",
        18: "MANIFEST",
    }

    try:
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name:
                name = _safe_decode(
                    resource_type.name.string
                )
            else:
                name = resource_type_map.get(
                    resource_type.struct.Id,
                    str(resource_type.struct.Id),
                )

            type_names.append(name)

            if name.upper() == "MANIFEST":
                result["manifest_present"] = True

            try:
                result["resource_count"] += len(
                    resource_type.directory.entries
                )
            except Exception:
                result["resource_count"] += 1

    except Exception:
        pass

    result["types"] = sorted(
        set(type_names)
    )

    return result


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

def _analyze_signature(pe: pefile.PE) -> Dict[str, Any]:
    """
    Detect whether an Authenticode certificate table exists.

    This does not claim the certificate is trusted or valid.
    """

    result = {
        "present": False,
        "size": 0,
        "offset": 0,
    }

    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]

        result["offset"] = int(directory.VirtualAddress)
        result["size"] = int(directory.Size)

        result["present"] = (
            result["offset"] > 0
            and result["size"] > 0
        )

    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Packer heuristics
# ---------------------------------------------------------------------------

def _packer_heuristics(
    sections: Dict[str, Any],
    imports: Dict[str, Any],
    strings: Dict[str, Any],
) -> Dict[str, Any]:
    """Heuristic detection of packing/obfuscation."""

    indicators = []
    score = 0

    suspicious_sections = sections.get(
        "suspicious_sections",
        [],
    )

    for section in suspicious_sections:
        reasons = section.get(
            "reasons",
            [],
        )

        if any(
            "packer" in reason.lower()
            or "pack" in reason.lower()
            for reason in reasons
        ):
            indicators.append(
                f"packer-like section: {section.get('name')}"
            )
            score += 3

        if any(
            "entropy" in reason.lower()
            for reason in reasons
        ):
            indicators.append(
                f"high entropy section: {section.get('name')}"
            )
            score += 2

    if strings.get("count", 0) < 20:
        indicators.append(
            "Very low printable-string count"
        )
        score += 1

    if imports.get("function_count", 0) < 5:
        indicators.append(
            "Very small import table"
        )
        score += 1

    if score >= 5:
        classification = "HIGH"
    elif score >= 3:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    return {
        "score": score,
        "classification": classification,
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _build_findings(
    headers: Dict[str, Any],
    sections: Dict[str, Any],
    imports: Dict[str, Any],
    strings: Dict[str, Any],
    indicators: Dict[str, Any],
    mitigations: Dict[str, Any],
    tls: Dict[str, Any],
    overlay: Dict[str, Any],
    signature: Dict[str, Any],
    packer: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Create ASAF-style static security findings."""

    findings = []

    def add(
        severity: str,
        title: str,
        description: str,
        category: str,
        evidence: Optional[Any] = None,
        confidence: str = "MEDIUM",
    ):
        findings.append(
            {
                "severity": severity,
                "title": title,
                "description": description,
                "category": category,
                "confidence": confidence,
                "evidence": evidence,
            }
        )

    # ---------------------------------------------------------------
    # Architecture
    # ---------------------------------------------------------------

    if headers.get("architecture") == "Unknown":
        add(
            "WARNING",
            "Unknown PE architecture",
            "The PE machine type could not be mapped to a known architecture.",
            "PE_HEADERS",
            headers.get("machine"),
        )

    # ---------------------------------------------------------------
    # Section issues
    # ---------------------------------------------------------------

    for item in sections.get(
        "suspicious_sections",
        [],
    ):
        name = item.get("name", "")
        reasons = item.get("reasons", [])

        if any(
            "executable and writable"
            in reason.lower()
            for reason in reasons
        ):
            add(
                "HIGH",
                "Executable writable section",
                (
                    f"PE section {name!r} is both executable "
                    "and writable. This can be associated with "
                    "runtime code generation or unpacking."
                ),
                "SECTIONS",
                reasons,
                "MEDIUM",
            )

        if any(
            "entropy"
            in reason.lower()
            for reason in reasons
        ):
            add(
                "WARNING",
                "High entropy PE section",
                (
                    f"Section {name!r} has unusually high entropy. "
                    "This can indicate compression, encryption, "
                    "or packing, but is not proof of maliciousness."
                ),
                "OBFUSCATION",
                reasons,
                "MEDIUM",
            )

        if any(
            "packer"
            in reason.lower()
            for reason in reasons
        ):
            add(
                "WARNING",
                "Packer-like PE section",
                (
                    f"Section {name!r} resembles a known "
                    "packer-related section name."
                ),
                "PACKING",
                reasons,
                "MEDIUM",
            )

    # ---------------------------------------------------------------
    # Suspicious APIs
    # ---------------------------------------------------------------

    suspicious_imports = imports.get(
        "suspicious_imports",
        [],
    )

    if suspicious_imports:
        grouped = {}

        for item in suspicious_imports:
            dll = item.get("dll", "")
            grouped.setdefault(dll, []).append(
                item.get("function", "")
            )

        add(
            "WARNING",
            "Suspicious Windows API imports",
            (
                "The PE imports APIs commonly associated with "
                "process manipulation, code injection, persistence, "
                "networking, registry access, or command execution. "
                "Imports alone do not prove malicious behavior."
            ),
            "IMPORTS",
            grouped,
            "MEDIUM",
        )

    # ---------------------------------------------------------------
    # PowerShell
    # ---------------------------------------------------------------

    powershell = [
        item
        for item in indicators
        if item.get("category") == "POWERSHELL"
    ]

    if powershell:
        add(
            "HIGH",
            "PowerShell indicators detected",
            (
                "Static strings contain PowerShell-related "
                "execution or download indicators."
            ),
            "POWERSHELL",
            powershell[:50],
            "MEDIUM",
        )

    # ---------------------------------------------------------------
    # Command execution
    # ---------------------------------------------------------------

    command_indicators = [
        item
        for item in indicators
        if item.get("category") == "COMMAND_EXECUTION"
    ]

    if command_indicators:
        add(
            "WARNING",
            "Command execution indicators detected",
            (
                "Static strings contain Windows command-shell "
                "or script execution indicators."
            ),
            "COMMAND_EXECUTION",
            command_indicators[:50],
            "MEDIUM",
        )

    # ---------------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------------

    persistence = [
        item
        for item in indicators
        if item.get("category") == "PERSISTENCE"
    ]

    if persistence:
        add(
            "HIGH",
            "Registry persistence indicators detected",
            (
                "Static strings reference Windows Run/RunOnce "
                "registry persistence locations."
            ),
            "PERSISTENCE",
            persistence[:50],
            "MEDIUM",
        )

    # ---------------------------------------------------------------
    # Network indicators
    # ---------------------------------------------------------------

    if indicators:
        # Actual network indicators are supplied separately.
        pass

    # ---------------------------------------------------------------
    # TLS callbacks
    # ---------------------------------------------------------------

    if tls.get("callback_count", 0) > 0:
        add(
            "WARNING",
            "TLS callbacks detected",
            (
                "The PE contains TLS callbacks. TLS callbacks can "
                "execute before the normal program entry point."
            ),
            "TLS",
            tls.get("callbacks"),
            "MEDIUM",
        )

    # ---------------------------------------------------------------
    # Overlay
    # ---------------------------------------------------------------

    if overlay.get("present"):
        add(
            "INFO",
            "PE overlay detected",
            (
                "Additional data exists after the end of the "
                "normal PE image."
            ),
            "OVERLAY",
            {
                "size": overlay.get("size"),
                "offset": overlay.get("offset"),
                "sha256": overlay.get("sha256"),
            },
            "HIGH",
        )

    # ---------------------------------------------------------------
    # Signature
    # ---------------------------------------------------------------

    if not signature.get("present"):
        add(
            "INFO",
            "No embedded Authenticode certificate detected",
            (
                "The PE does not contain an embedded Authenticode "
                "certificate table. This does not mean the file "
                "is malicious."
            ),
            "SIGNATURE",
            None,
            "HIGH",
        )
    else:
        add(
            "SECURE",
            "Authenticode certificate table present",
            (
                "The PE contains an embedded certificate table. "
                "Certificate validity and trust are not established "
                "by this static check."
            ),
            "SIGNATURE",
            {
                "size": signature.get("size"),
                "offset": signature.get("offset"),
            },
            "HIGH",
        )

    # ---------------------------------------------------------------
    # ASLR
    # ---------------------------------------------------------------

    if not mitigations.get("aslr"):
        add(
            "WARNING",
            "ASLR is not enabled",
            (
                "The PE does not advertise the Dynamic Base flag "
                "required for normal ASLR behavior."
            ),
            "MITIGATIONS",
            None,
            "HIGH",
        )

    # ---------------------------------------------------------------
    # DEP
    # ---------------------------------------------------------------

    if not mitigations.get("dep_nx"):
        add(
            "WARNING",
            "DEP/NX compatibility is not enabled",
            (
                "The PE does not advertise NX compatibility."
            ),
            "MITIGATIONS",
            None,
            "HIGH",
        )

    # ---------------------------------------------------------------
    # CFG
    # ---------------------------------------------------------------

    if not mitigations.get("cfg"):
        add(
            "INFO",
            "Control Flow Guard is not enabled",
            (
                "The PE does not advertise the Guard CF "
                "mitigation."
            ),
            "MITIGATIONS",
            None,
            "HIGH",
        )

    # ---------------------------------------------------------------
    # Packer
    # ---------------------------------------------------------------

    if packer.get("classification") == "HIGH":
        add(
            "WARNING",
            "Possible packing or obfuscation",
            (
                "Multiple static indicators suggest that the "
                "binary may be packed or obfuscated."
            ),
            "PACKING",
            packer.get("indicators"),
            "LOW",
        )

    elif packer.get("classification") == "MEDIUM":
        add(
            "INFO",
            "Possible packing or obfuscation",
            (
                "Some static indicators suggest possible "
                "compression, packing, or obfuscation."
            ),
            "PACKING",
            packer.get("indicators"),
            "LOW",
        )

    return findings


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

def _calculate_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate a static-analysis risk score.

    Starts at 100.
    Findings reduce the score according to severity.

    This score represents static PE indicators only.
    """

    score = 100

    deductions = {
        "HIGH": 15,
        "WARNING": 8,
        "INFO": 2,
        "HOTSPOT": 10,
        "SECURE": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO",
        )

        score -= deductions.get(
            severity,
            0,
        )

    score = max(
        0,
        min(100, score),
    )

    high = sum(
        1
        for item in findings
        if item.get("severity") == "HIGH"
    )

    warning = sum(
        1
        for item in findings
        if item.get("severity") == "WARNING"
    )

    info = sum(
        1
        for item in findings
        if item.get("severity") == "INFO"
    )

    secure = sum(
        1
        for item in findings
        if item.get("severity") == "SECURE"
    )

    if score >= 85:
        risk = "LOW"
    elif score >= 70:
        risk = "MEDIUM"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    return {
        "score": score,
        "risk": risk,
        "severity_counts": {
            "high": high,
            "warning": warning,
            "info": info,
            "secure": secure,
        },
    }


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_exe(
    file_path: str,
    max_string_count: int = 10000,
) -> Dict[str, Any]:
    """
    Analyze a Windows PE file statically.

    Parameters
    ----------
    file_path:
        Path to .exe/.dll.

    max_string_count:
        Maximum number of strings retained in output.

    Returns
    -------
    dict
        JSON-serializable analysis result.
    """

    if not file_path:
        raise ValueError("file_path is required")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"PE file does not exist: {file_path}"
        )

    file_size = os.path.getsize(file_path)

    result: Dict[str, Any] = {
        "analyzer": "ASAF Static PE Analyzer",
        "analyzer_version": "1.0.0",
        "analysis_type": "STATIC",
        "execution": False,
        "file": {
            "name": os.path.basename(file_path),
            "path": file_path,
            "size": file_size,
            "size_human": _human_size(file_size),
        },
        "valid_pe": False,
        "error": None,
    }

    # ---------------------------------------------------------------
    # Hashes
    # ---------------------------------------------------------------

    try:
        result["hashes"] = _hash_file(file_path)
    except Exception as exc:
        result["hashes"] = {}
        result["error"] = (
            f"Hash calculation failed: {exc}"
        )

    # ---------------------------------------------------------------
    # PE parsing
    # ---------------------------------------------------------------

    pe: Optional[pefile.PE] = None

    try:
        pe = pefile.PE(
            name=file_path,
            fast_load=False,
        )

        result["valid_pe"] = True

    except pefile.PEFormatError as exc:
        result["error"] = (
            f"Invalid PE file: {exc}"
        )

        result["score"] = {
            "score": 0,
            "risk": "CRITICAL",
            "severity_counts": {
                "high": 1,
                "warning": 0,
                "info": 0,
                "secure": 0,
            },
        }

        result["findings"] = [
            {
                "severity": "HIGH",
                "title": "Invalid PE file",
                "description": (
                    "The uploaded file could not be parsed "
                    "as a valid Windows Portable Executable."
                ),
                "category": "PE_FORMAT",
                "confidence": "HIGH",
                "evidence": str(exc),
            }
        ]

        return result

    except Exception as exc:
        result["error"] = (
            f"PE parsing failed: {exc}"
        )

        return result

    try:
        # -----------------------------------------------------------
        # Headers
        # -----------------------------------------------------------

        headers = _analyze_headers(pe)

        # -----------------------------------------------------------
        # Sections
        # -----------------------------------------------------------

        sections = _analyze_sections(pe)

        # -----------------------------------------------------------
        # Imports
        # -----------------------------------------------------------

        imports = _analyze_imports(pe)

        # -----------------------------------------------------------
        # Exports
        # -----------------------------------------------------------

        exports = _analyze_exports(pe)

        # -----------------------------------------------------------
        # Strings
        # -----------------------------------------------------------

        string_result = _read_strings(
            file_path,
            minimum_length=5,
        )

        string_list = string_result.get(
            "strings",
            [],
        )

        string_result["strings"] = string_list[
            :max_string_count
        ]

        # -----------------------------------------------------------
        # Network indicators
        # -----------------------------------------------------------

        network = _find_network_indicators(
            string_list
        )

        # -----------------------------------------------------------
        # Static string indicators
        # -----------------------------------------------------------

        indicators = _find_string_indicators(
            string_list
        )

        # -----------------------------------------------------------
        # Security mitigations
        # -----------------------------------------------------------

        mitigations = _analyze_mitigations(pe)

        # -----------------------------------------------------------
        # TLS
        # -----------------------------------------------------------

        tls = _analyze_tls(pe)

        # -----------------------------------------------------------
        # Overlay
        # -----------------------------------------------------------

        overlay = _analyze_overlay(
            pe,
            file_path,
        )

        # -----------------------------------------------------------
        # Resources
        # -----------------------------------------------------------

        resources = _analyze_resources(pe)

        # -----------------------------------------------------------
        # Signature
        # -----------------------------------------------------------

        signature = _analyze_signature(pe)

        # -----------------------------------------------------------
        # Packer heuristics
        # -----------------------------------------------------------

        packer = _packer_heuristics(
            sections,
            imports,
            string_result,
        )

        # -----------------------------------------------------------
        # Findings
        # -----------------------------------------------------------

        findings = _build_findings(
            headers=headers,
            sections=sections,
            imports=imports,
            strings=string_result,
            indicators=indicators,
            mitigations=mitigations,
            tls=tls,
            overlay=overlay,
            signature=signature,
            packer=packer,
        )

        # -----------------------------------------------------------
        # Network findings
        # -----------------------------------------------------------

        if network["urls"]:
            findings.append(
                {
                    "severity": "WARNING",
                    "title": "URLs found in PE strings",
                    "description": (
                        "One or more URLs were found in "
                        "the static string table."
                    ),
                    "category": "NETWORK",
                    "confidence": "HIGH",
                    "evidence": network["urls"][:100],
                }
            )

        if network["ips"]:
            findings.append(
                {
                    "severity": "WARNING",
                    "title": "IPv4 addresses found in PE strings",
                    "description": (
                        "IPv4 addresses were found in "
                        "the static string table."
                    ),
                    "category": "NETWORK",
                    "confidence": "HIGH",
                    "evidence": network["ips"][:100],
                }
            )

        # -----------------------------------------------------------
        # Score
        # -----------------------------------------------------------

        score = _calculate_score(
            findings
        )

        # -----------------------------------------------------------
        # Final result
        # -----------------------------------------------------------

        result.update(
            {
                "headers": headers,
                "sections": sections,
                "imports": imports,
                "exports": exports,
                "strings": string_result,
                "network": network,
                "indicators": indicators,
                "mitigations": mitigations,
                "tls": tls,
                "overlay": overlay,
                "resources": resources,
                "signature": signature,
                "packer": packer,
                "findings": findings,
                "score": score,
            }
        )

    except Exception as exc:
        result["error"] = (
            f"Static PE analysis failed: {exc}"
        )

    finally:
        try:
            pe.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

def analyze_pe(
    file_path: str,
    max_string_count: int = 10000,
) -> Dict[str, Any]:
    """Alias for analyze_exe()."""
    return analyze_exe(
        file_path,
        max_string_count=max_string_count,
    )


def analyze(
    file_path: str,
    max_string_count: int = 10000,
) -> Dict[str, Any]:
    """Generic analyzer entry point."""
    return analyze_exe(
        file_path,
        max_string_count=max_string_count,
    )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _human_size(size: int) -> str:
    """Convert bytes to a human-readable size."""

    value = float(size)

    for unit in (
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ):
        if value < 1024:
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} PB"


# ---------------------------------------------------------------------------
# Command-line testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python exe_analyzer.py <file.exe>"
        )
        sys.exit(1)

    target = sys.argv[1]

    try:
        analysis = analyze_exe(target)

        print(
            json.dumps(
                analysis,
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )

    except Exception as exc:
        print(
            f"Analysis failed: {exc}"
        )
        sys.exit(1)