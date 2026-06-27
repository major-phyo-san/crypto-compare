from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CPUProfile:
    model_name: str
    manufacturer: str
    physical_cores: int | None
    logical_cores: int | None
    max_clock_mhz: int | None
    idle_watts: float
    tdp_watts: float
    tdp_source: str
    detection_source: str

    @property
    def tdp_confidence(self) -> str:
        if self.tdp_source == "exact_model":
            return "high"
        if self.tdp_source == "fallback_default":
            return "low"
        return "medium"

    @property
    def tdp_label(self) -> str:
        return f"{self.tdp_watts:.0f}W ({self.tdp_source})"

    @property
    def tdp_note(self) -> str:
        if self.tdp_source == "exact_model":
            return "TDP matched from an exact CPU model entry."
        if self.tdp_source == "fallback_default":
            return "TDP fell back to a generic default because no model or family match was found."
        return "TDP estimated from a CPU family or suffix heuristic rather than an exact model entry."

    @property
    def power_envelope_label(self) -> str:
        return f"{self.idle_watts:.1f}W to {self.tdp_watts:.0f}W"

    @property
    def power_envelope_note(self) -> str:
        return (
            "Estimated power uses a simple CPU envelope: idle_watts + utilization * "
            "(tdp_watts - idle_watts)."
        )

_CPU_TDP_MAPPING_PATH = Path(__file__).with_name("cpu_tdp_mapping.json")


def _load_exact_tdp_by_model() -> dict[str, float]:
    try:
        payload = json.loads(_CPU_TDP_MAPPING_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(payload, dict):
        return {}

    mappings: dict[str, float] = {}
    for model_name, tdp_watts in payload.items():
        if not isinstance(model_name, str):
            continue
        try:
            mappings[_normalize_model_name(model_name)] = float(tdp_watts)
        except (TypeError, ValueError):
            continue
    return mappings

def detect_cpu_profile() -> CPUProfile:
    cpu_info = _detect_windows_cpu() or _detect_portable_cpu()
    model_name = cpu_info.get("name") or "Unknown CPU"
    manufacturer = cpu_info.get("manufacturer") or _infer_manufacturer(model_name)
    physical_cores = _to_int(cpu_info.get("physical_cores"))
    logical_cores = _to_int(cpu_info.get("logical_cores"))
    max_clock_mhz = _to_int(cpu_info.get("max_clock_mhz"))
    tdp_watts, tdp_source = _map_tdp(model_name)
    idle_watts = _estimate_idle_watts(tdp_watts, physical_cores, manufacturer)

    return CPUProfile(
        model_name=model_name,
        manufacturer=manufacturer,
        physical_cores=physical_cores,
        logical_cores=logical_cores,
        max_clock_mhz=max_clock_mhz,
        idle_watts=idle_watts,
        tdp_watts=tdp_watts,
        tdp_source=tdp_source,
        detection_source=cpu_info.get("detection_source", "fallback"),
    )


def _detect_windows_cpu() -> dict[str, object] | None:
    if os.name != "nt":
        return None

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-CimInstance Win32_Processor | "
            "Select-Object -First 1 Name,Manufacturer,NumberOfCores,"
            "NumberOfLogicalProcessors,MaxClockSpeed | ConvertTo-Json -Compress"
        ),
    ]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    stdout = result.stdout.strip()
    if not stdout:
        return None

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    return {
        "name": str(payload.get("Name", "")).strip(),
        "manufacturer": str(payload.get("Manufacturer", "")).strip(),
        "physical_cores": payload.get("NumberOfCores"),
        "logical_cores": payload.get("NumberOfLogicalProcessors"),
        "max_clock_mhz": payload.get("MaxClockSpeed"),
        "detection_source": "win32_processor",
    }


def _detect_portable_cpu() -> dict[str, object] | None:
    model_name = (
        platform.processor().strip()
        or platform.uname().processor.strip()
        or os.environ.get("PROCESSOR_IDENTIFIER", "").strip()
    )
    if not model_name:
        return None

    return {
        "name": model_name,
        "manufacturer": _infer_manufacturer(model_name),
        "physical_cores": os.cpu_count(),
        "logical_cores": os.cpu_count(),
        "max_clock_mhz": None,
        "detection_source": "platform",
    }


def _infer_manufacturer(model_name: str) -> str:
    upper_name = model_name.upper()
    if "INTEL" in upper_name:
        return "Intel"
    if "AMD" in upper_name or "RYZEN" in upper_name:
        return "AMD"
    if "APPLE" in upper_name or upper_name.startswith("M1") or upper_name.startswith("M2"):
        return "Apple"
    return "Unknown"


def _map_tdp(model_name: str) -> tuple[float, str]:
    normalized = _normalize_model_name(model_name)
    exact_match = _EXACT_TDP_BY_MODEL.get(normalized)
    if exact_match is not None:
        return exact_match, "exact_model"

    intel_tdp = _map_intel_tdp(normalized)
    if intel_tdp is not None:
        return intel_tdp

    amd_tdp = _map_amd_tdp(normalized)
    if amd_tdp is not None:
        return amd_tdp

    return 65.0, "fallback_default"


def _map_intel_tdp(model_name: str) -> tuple[float, str] | None:
    if "INTEL" not in model_name and "CORE" not in model_name and "CELERON" not in model_name:
        return None

    suffix_match = re.search(r"\b([A-Z]{1,3}\d{0,2}|G[1-9])\b(?!(?:HZ))", model_name)
    if suffix_match:
        suffix = suffix_match.group(1)
        if suffix in {"HX", "XE"}:
            return 55.0, f"intel_family_suffix:{suffix}"
        if suffix in {"HK", "H"}:
            return 45.0, f"intel_family_suffix:{suffix}"
        if suffix == "HS":
            return 35.0, f"intel_family_suffix:{suffix}"
        if suffix in {"P", "G7", "G4"}:
            return 28.0, f"intel_family_suffix:{suffix}"
        if suffix in {"U", "G1"}:
            return 15.0, f"intel_family_suffix:{suffix}"
        if suffix == "Y":
            return 5.0, f"intel_family_suffix:{suffix}"
        if suffix in {"T"}:
            return 35.0, f"intel_family_suffix:{suffix}"
        if suffix in {"K", "KF", "KS"}:
            return 125.0, f"intel_family_suffix:{suffix}"
        if suffix in {"F", "X"}:
            return 65.0, f"intel_family_suffix:{suffix}"

    if "ATOM" in model_name:
        return 10.0, "intel_family:atom"
    if "CELERON" in model_name or "PENTIUM" in model_name:
        return 15.0, "intel_family:entry_mobile_or_low_power"
    if "CORE(TM) I" in model_name:
        return 65.0, "intel_family:generic_core"

    return 65.0, "intel_family:generic"


def _map_amd_tdp(model_name: str) -> tuple[float, str] | None:
    if "AMD" not in model_name and "RYZEN" not in model_name:
        return None

    suffix_match = re.search(r"\b(\d{4,5}[A-Z]{0,2}|[A-Z]{1,2})\b", model_name)
    if suffix_match:
        suffix_token = suffix_match.group(1)
        for suffix in ("HX", "HS", "H", "U", "GE", "X3D", "X"):
            if suffix_token.endswith(suffix):
                if suffix == "HX":
                    return 55.0, f"amd_family_suffix:{suffix}"
                if suffix == "HS":
                    return 35.0, f"amd_family_suffix:{suffix}"
                if suffix == "H":
                    return 45.0, f"amd_family_suffix:{suffix}"
                if suffix == "U":
                    return 15.0, f"amd_family_suffix:{suffix}"
                if suffix == "GE":
                    return 35.0, f"amd_family_suffix:{suffix}"
                if suffix == "X3D":
                    return 120.0, f"amd_family_suffix:{suffix}"
                if suffix == "X":
                    return 105.0, f"amd_family_suffix:{suffix}"

    if "THREADRIPPER" in model_name:
        return 280.0, "amd_family:threadripper"
    if "EPYC" in model_name:
        return 200.0, "amd_family:epyc"
    if "RYZEN" in model_name:
        return 65.0, "amd_family:generic_ryzen"

    return 65.0, "amd_family:generic"


def _normalize_model_name(model_name: str) -> str:
    return " ".join(model_name.upper().split())


_EXACT_TDP_BY_MODEL = _load_exact_tdp_by_model()


def _estimate_idle_watts(
    tdp_watts: float,
    physical_cores: int | None,
    manufacturer: str,
) -> float:
    if tdp_watts <= 10:
        base_idle = 2.0
    elif tdp_watts <= 20:
        base_idle = 3.0
    elif tdp_watts <= 35:
        base_idle = 5.0
    elif tdp_watts <= 65:
        base_idle = 8.0
    else:
        base_idle = 12.0

    if manufacturer.upper().startswith("AMD"):
        base_idle += 0.5
    elif manufacturer.upper().startswith("APPLE"):
        base_idle -= 0.5

    if physical_cores is not None and physical_cores >= 12:
        base_idle += 2.0
    elif physical_cores is not None and physical_cores >= 8:
        base_idle += 1.0

    return max(1.0, min(base_idle, tdp_watts * 0.6))


def _to_int(value: object) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
