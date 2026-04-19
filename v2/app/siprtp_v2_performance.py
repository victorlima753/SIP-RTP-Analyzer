#!/usr/bin/env python3
"""Performance profile helpers for SIP/RTP Analyzer V2."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Any


PROFILE_LABELS = {
    "safe": "Seguro",
    "balanced": "Equilibrado",
    "turbo": "Turbo",
}
PROFILE_ALIASES = {
    "safe": "safe",
    "seguro": "safe",
    "balanced": "balanced",
    "equilibrado": "balanced",
    "turbo": "turbo",
}
PROFILE_FACTORS = {
    "safe": 0.25,
    "balanced": 0.45,
    "turbo": 0.70,
}
MEMORY_CAPS = {
    "safe": (1, 2, 4, 6),
    "balanced": (2, 5, 8, 12),
    "turbo": (3, 8, 12, 18),
}


@dataclass(frozen=True)
class MemoryInfo:
    total_bytes: int | None
    available_bytes: int | None

    @property
    def total_gb(self) -> float | None:
        return round(self.total_bytes / (1024**3), 2) if self.total_bytes else None

    @property
    def available_gb(self) -> float | None:
        return round(self.available_bytes / (1024**3), 2) if self.available_bytes else None


@dataclass(frozen=True)
class WorkerPlan:
    profile: str
    profile_label: str
    workers: int
    auto_workers: bool
    cpu_count: int
    candidate_count: int
    memory_total_gb: float | None
    memory_available_gb: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "profile_label": self.profile_label,
            "workers": self.workers,
            "auto_workers": self.auto_workers,
            "cpu_count": self.cpu_count,
            "candidate_count": self.candidate_count,
            "memory_total_gb": self.memory_total_gb,
            "memory_available_gb": self.memory_available_gb,
        }


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def normalize_profile(value: str | None) -> str:
    key = (value or "balanced").strip().lower()
    return PROFILE_ALIASES.get(key, "balanced")


def detect_memory_info() -> MemoryInfo:
    if os.name != "nt":
        return MemoryInfo(None, None)
    try:
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
            return MemoryInfo(int(status.ullTotalPhys), int(status.ullAvailPhys))
    except Exception:
        pass
    return MemoryInfo(None, None)


def memory_cap_for_profile(profile: str, total_gb: float | None) -> int | None:
    if total_gb is None:
        return None
    caps = MEMORY_CAPS[profile]
    if total_gb <= 8:
        return caps[0]
    if total_gb <= 16:
        return caps[1]
    if total_gb <= 32:
        return caps[2]
    return caps[3]


def parse_worker_override(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    clean = str(value).strip().lower()
    if not clean or clean == "auto":
        return None
    try:
        parsed = int(clean)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def calculate_worker_plan(
    profile: str | None = "balanced",
    workers: str | int | None = None,
    candidate_count: int = 1,
    cpu_count: int | None = None,
    memory_info: MemoryInfo | None = None,
) -> WorkerPlan:
    normalized_profile = normalize_profile(profile)
    candidates = max(1, int(candidate_count or 1))
    cpus = max(1, int(cpu_count or os.cpu_count() or 4))
    memory = memory_info or detect_memory_info()
    override = parse_worker_override(workers)
    if override is not None:
        selected = override
        auto_workers = False
    else:
        selected = max(1, round(cpus * PROFILE_FACTORS[normalized_profile]))
        selected = min(selected, max(1, cpus - 1)) if cpus > 1 else 1
        cap = memory_cap_for_profile(normalized_profile, memory.total_gb)
        if cap is not None:
            selected = min(selected, cap)
        auto_workers = True
    selected = max(1, min(selected, candidates))
    return WorkerPlan(
        profile=normalized_profile,
        profile_label=PROFILE_LABELS[normalized_profile],
        workers=selected,
        auto_workers=auto_workers,
        cpu_count=cpus,
        candidate_count=candidates,
        memory_total_gb=memory.total_gb,
        memory_available_gb=memory.available_gb,
    )
