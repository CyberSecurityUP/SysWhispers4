#!/usr/bin/env python3
"""
SysWhispers4 — Syscall Table Updater
Fetches the latest NT syscall numbers from j00ru/windows-syscalls and
updates data/syscalls_nt_x64.json and data/syscalls_nt_x86.json.

Usage:
  python scripts/update_syscall_table.py
  python scripts/update_syscall_table.py --arch x86
  python scripts/update_syscall_table.py --arch x64,x86
  python scripts/update_syscall_table.py --out custom_table.json

Requirements:
  Standard library only (no pip dependencies).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError

# ---------------------------------------------------------------------------
# j00ru table URLs (raw CSV from GitHub)
# ---------------------------------------------------------------------------
JORU_BASE = "https://raw.githubusercontent.com/j00ru/windows-syscalls/master"
CSV_URLS = {
    "x64": f"{JORU_BASE}/x64/csv/nt.csv",
    "x86": f"{JORU_BASE}/x86/csv/nt.csv",
}

# ---------------------------------------------------------------------------
# Unified human-readable label → (short build_key, display_label)
# Covers every column seen in both x64 and x86 j00ru CSVs.
# Win10/Win11 entries use actual build numbers for cross-arch consistency.
# ---------------------------------------------------------------------------
VER_MAP: Dict[str, Tuple[str, str]] = {
    # ---- x86-only: legacy ----
    "Windows NT 3.x (3.1)":         ("nt3.1",         "Windows NT 3.1"),
    "Windows NT 3.x (3.5)":         ("nt3.5",         "Windows NT 3.5"),
    "Windows NT 3.x (3.51)":        ("nt3.51",        "Windows NT 3.51"),
    "Windows NT 4.0 (SP0)":         ("nt4.0",         "Windows NT 4.0 RTM"),
    "Windows NT 4.0 (SP1)":         ("nt4.0_sp1",     "Windows NT 4.0 SP1"),
    "Windows NT 4.0 (SP2)":         ("nt4.0_sp2",     "Windows NT 4.0 SP2"),
    "Windows NT 4.0 (SP3)":         ("nt4.0_sp3",     "Windows NT 4.0 SP3"),
    "Windows NT 4.0 (SP3 TSE)":     ("nt4.0_sp3_tse", "Windows NT 4.0 SP3 TSE"),
    "Windows NT 4.0 (SP4)":         ("nt4.0_sp4",     "Windows NT 4.0 SP4"),
    "Windows NT 4.0 (SP5)":         ("nt4.0_sp5",     "Windows NT 4.0 SP5"),
    "Windows NT 4.0 (SP6)":         ("nt4.0_sp6",     "Windows NT 4.0 SP6"),
    "Windows 2000 (SP0)":           ("2000_sp0",      "Windows 2000 RTM"),
    "Windows 2000 (SP1)":           ("2000_sp1",      "Windows 2000 SP1"),
    "Windows 2000 (SP2)":           ("2000_sp2",      "Windows 2000 SP2"),
    "Windows 2000 (SP3)":           ("2000_sp3",      "Windows 2000 SP3"),
    "Windows 2000 (SP4)":           ("2000_sp4",      "Windows 2000 SP4"),
    # ---- shared x64/x86 ----
    "Windows XP (SP0)":             ("xp_sp0",        "Windows XP RTM"),
    "Windows XP (SP1)":             ("xp_sp1",        "Windows XP SP1"),
    "Windows XP (SP2)":             ("xp_sp2",        "Windows XP SP2"),
    "Windows XP (SP3)":             ("xp_sp3",        "Windows XP SP3"),
    "Windows Server 2003 (SP0)":    ("2003_sp0",      "Windows Server 2003 RTM"),
    "Windows Server 2003 (SP1)":    ("2003_sp1",      "Windows Server 2003 SP1"),
    "Windows Server 2003 (SP2)":    ("2003_sp2",      "Windows Server 2003 SP2"),
    "Windows Server 2003 (R2)":     ("2003_r2",       "Windows Server 2003 R2"),
    "Windows Server 2003 (R2 SP2)": ("2003_r2_sp2",   "Windows Server 2003 R2 SP2"),
    "Windows Vista (SP0)":          ("vista_sp0",     "Windows Vista RTM"),
    "Windows Vista (SP1)":          ("vista_sp1",     "Windows Vista SP1"),
    "Windows Vista (SP2)":          ("vista_sp2",     "Windows Vista SP2"),
    "Windows 7 (SP0)":              ("7_sp0",         "Windows 7 RTM"),
    "Windows 7 (SP1)":              ("7_sp1",         "Windows 7 SP1"),
    "Windows 8 (8.0)":              ("8.0",           "Windows 8 RTM"),
    "Windows 8 (8.1)":              ("8.1",           "Windows 8.1 RTM"),
    # Win10 → actual build numbers (consistent across x64 and x86)
    "Windows 10 (1507)":            ("10240",         "Windows 10 1507 (build 10240)"),
    "Windows 10 (1511)":            ("10586",         "Windows 10 1511 (build 10586)"),
    "Windows 10 (1607)":            ("14393",         "Windows 10 1607 (build 14393)"),
    "Windows 10 (1703)":            ("15063",         "Windows 10 1703 (build 15063)"),
    "Windows 10 (1709)":            ("16299",         "Windows 10 1709 (build 16299)"),
    "Windows 10 (1803)":            ("17134",         "Windows 10 1803 (build 17134)"),
    "Windows 10 (1809)":            ("17763",         "Windows 10 1809 (build 17763)"),
    "Windows 10 (1903)":            ("18362",         "Windows 10 1903 (build 18362)"),
    "Windows 10 (1909)":            ("18363",         "Windows 10 1909 (build 18363)"),
    "Windows 10 (2004)":            ("19041",         "Windows 10 2004 (build 19041)"),
    "Windows 10 (20H2)":            ("19042",         "Windows 10 20H2 (build 19042)"),
    "Windows 10 (21H1)":            ("19043",         "Windows 10 21H1 (build 19043)"),
    "Windows 10 (21H2)":            ("19044",         "Windows 10 21H2 (build 19044)"),
    "Windows 10 (22H2)":            ("19045",         "Windows 10 22H2 (build 19045)"),
    # Win11 / Server (x64-only in j00ru CSVs)
    "Windows 11 and Server (Server 2022)":  ("20348", "Windows Server 2022 (build 20348)"),
    "Windows 11 and Server (11 21H2)":      ("22000", "Windows 11 21H2 (build 22000)"),
    "Windows 11 and Server (11 22H2)":      ("22621", "Windows 11 22H2 (build 22621)"),
    "Windows 11 and Server (11 23H2)":      ("22631", "Windows 11 23H2 (build 22631)"),
    "Windows 11 and Server (Server 23H2)":  ("25398", "Windows Server 2022 23H2 (build 25398)"),
    "Windows 11 and Server (11 24H2)":      ("26100", "Windows 11 24H2 (build 26100)"),
    "Windows 11 and Server (Server 2025)":  ("26100_srv", "Windows Server 2025 (build 26100)"),
    "Windows 11 and Server (11 25H2)":      ("26200", "Windows 11 25H2 (build 26200)"),
}


def _parse_header_col(ver_str: str) -> Optional[Tuple[str, str]]:
    """
    Return (build_key, display_label) for a CSV header column,
    or None if it should be skipped.

    Handles j00ru's human-readable format used in both x64 and x86 CSVs:
      "Windows 10 (1903)", "Windows NT 4.0 (SP3)", "Windows 11 and Server (11 24H2)"

    Also handles legacy dotted-version strings (kept for forward-compatibility):
      "10.0.19041.1", "6.1.7601.17514"
    """
    ver_str = ver_str.strip()
    if not ver_str:
        return None

    # Fast path: known label
    entry = VER_MAP.get(ver_str)
    if entry:
        return entry

    # Legacy dotted format (kept in case j00ru ever reverts): "10.0.19041.1"
    if re.match(r"^\d+\.\d+\.\d+", ver_str):
        parts = ver_str.split(".")
        try:
            major = int(parts[0])
            build = int(parts[2])
        except (IndexError, ValueError):
            return None
        key = str(build) if major >= 10 else f"{parts[1]}.{parts[2]}"
        return key, ver_str

    # Unknown: sanitize string as fallback key so we never lose data
    key = re.sub(r"[^a-zA-Z0-9._]", "_", ver_str).strip("_").lower()
    return key, ver_str


def fetch_csv(url: str) -> str:
    print(f"  [~] Fetching: {url}")
    req = Request(url, headers={"User-Agent": "SysWhispers4/1.0"})
    try:
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except URLError as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        sys.exit(1)


def parse_joru_csv(csv_text: str) -> dict:
    """
    Parse j00ru's CSV into our JSON format:
    { "FunctionName": { "build_key": ssn_int, ... }, ... }
    """
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    if not rows:
        return {}

    header = rows[0]
    version_cols = range(1, len(header))

    result: dict = {
        "_comment": "NT syscall numbers — generated by SysWhispers4/scripts/update_syscall_table.py",
        "_source":  "https://github.com/j00ru/windows-syscalls",
        "_format":  "FunctionName -> { build_key -> decimal_ssn }",
        "_windows_builds": {},
    }

    # Pre-parse all column headers once
    col_meta: Dict[int, Tuple[str, str]] = {}  # col_index → (key, label)
    for col in version_cols:
        parsed = _parse_header_col(header[col])
        if parsed:
            key, label = parsed
            col_meta[col] = (key, label)
            result["_windows_builds"][key] = label

    for row in rows[1:]:
        if not row or len(row) < 2:
            continue
        func_name = row[0].strip()
        if not func_name:
            continue

        func_entry: dict = {}
        for col, (build_key, _) in col_meta.items():
            if col >= len(row):
                break
            cell = row[col].strip()
            if not cell or cell.lower() in ("", "n/a", "-", "null"):
                continue
            try:
                ssn = int(cell, 16) if cell.startswith("0x") else int(cell)
            except ValueError:
                continue
            func_entry[build_key] = ssn

        if func_entry:
            result[func_name] = func_entry

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update SysWhispers4 syscall tables from j00ru/windows-syscalls",
    )
    parser.add_argument(
        "--arch",
        default="x64",
        help="Comma-separated architectures to fetch: x64, x86 (default: x64)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Custom output path (overrides the default data/ location)",
    )
    parser.add_argument(
        "--functions",
        default=None,
        help="Comma-separated list of functions to keep (default: all Nt* functions)",
    )
    args = parser.parse_args()

    data_dir = Path(__file__).parent.parent / "data"
    archs = [a.strip() for a in args.arch.split(",")]
    filter_funcs = set(f.strip() for f in args.functions.split(",")) if args.functions else None

    for arch in archs:
        if arch not in CSV_URLS:
            print(f"  [!] Unknown arch '{arch}'. Available: {list(CSV_URLS)}")
            continue

        csv_text = fetch_csv(CSV_URLS[arch])
        table = parse_joru_csv(csv_text)

        # Filter to Nt* functions only + keep metadata keys (_comment, _source, etc.)
        filtered = {k: v for k, v in table.items()
                    if k.startswith("_") or k.startswith("Nt")}

        if filter_funcs:
            filtered = {k: v for k, v in filtered.items()
                        if k.startswith("_") or k in filter_funcs}

        out_path = Path(args.out) if args.out else data_dir / f"syscalls_nt_{arch}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(filtered, indent=2, sort_keys=False), encoding="utf-8")
        n_funcs = sum(1 for k in filtered if not k.startswith("_"))
        print(f"  [+] Written {n_funcs} functions ({arch}) → {out_path}")

    print("  [+] Syscall table update complete.")


if __name__ == "__main__":
    main()
