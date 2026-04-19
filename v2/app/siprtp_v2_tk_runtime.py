#!/usr/bin/env python3
"""Tcl/Tk runtime setup for SIP/RTP Analyzer V2."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def configure_tcl_runtime() -> None:
    """Use a Tcl/Tk runtime from a stable path before importing Tkinter."""

    def tcl_path(path: Path) -> str:
        return str(path).replace("\\", "/")

    preferred = os.environ.get("SIPRTP_TK_RUNTIME")
    program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    target_roots = [Path(preferred)] if preferred else [program_data / "SIPRTPAnalyzer" / "tk_runtime"]

    module_dir = Path(__file__).resolve().parent
    root_dir = module_dir.parents[1]
    sources: list[Path] = []
    if hasattr(sys, "_MEIPASS"):
        sources.append(Path(sys._MEIPASS) / "tcl")  # type: ignore[attr-defined]
    sources.extend(
        [
            module_dir / "tk_runtime" / "tcl",
            root_dir / "tk_runtime" / "tcl",
            Path(sys.prefix) / "tcl",
            Path(sys.base_prefix) / "tcl",
        ]
    )
    source = next(
        (
            candidate
            for candidate in sources
            if (candidate / "tcl8.6" / "init.tcl").exists()
            and (candidate / "tk8.6" / "tk.tcl").exists()
        ),
        None,
    )

    for target_root in target_roots:
        target_tcl = target_root / "tcl"
        target_tcl86 = target_tcl / "tcl8.6"
        target_tk86 = target_tcl / "tk8.6"
        target_ready = (target_tcl86 / "init.tcl").exists() and (target_tk86 / "tk.tcl").exists()
        if not target_ready and source is not None:
            try:
                target_root.mkdir(parents=True, exist_ok=True)
                if target_tcl.exists():
                    shutil.rmtree(target_tcl, ignore_errors=True)
                shutil.copytree(source, target_tcl)
            except OSError:
                continue
        if (target_tcl86 / "init.tcl").exists() and (target_tk86 / "tk.tcl").exists():
            os.environ["TCL_LIBRARY"] = tcl_path(target_tcl86)
            os.environ["TK_LIBRARY"] = tcl_path(target_tk86)
            return

    if source is not None:
        source_tcl86 = source / "tcl8.6"
        source_tk86 = source / "tk8.6"
        if (source_tcl86 / "init.tcl").exists() and (source_tk86 / "tk.tcl").exists():
            os.environ["TCL_LIBRARY"] = tcl_path(source_tcl86)
            os.environ["TK_LIBRARY"] = tcl_path(source_tk86)
