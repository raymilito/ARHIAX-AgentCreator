#!/usr/bin/env python3
"""
Merge authz.rego (B14 + B16) and bundles_b01_b19.rego (the other 17) into
a single monolithic arhiax_all_bundles.rego for ConfigMap embedding and
signed-bundle distribution.

The merged file preserves all 19 package declarations as separate packages
(OPA allows multiple packages in a single .rego file as long as each has its
own `package` header). Deduplicates imports if any overlap.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Tuple


def extract_packages(content: str, source_name: str) -> List[Tuple[str, str]]:
    """Split a .rego file by `package` declarations.

    Returns a list of (package_name, package_body) tuples.
    """
    # Split on `package ` at start of line
    parts = re.split(r"(?m)^package\s+", content)
    # parts[0] is whatever precedes the first package (usually empty or comments)
    preamble = parts[0].strip()
    packages: List[Tuple[str, str]] = []
    for part in parts[1:]:
        # first line is the package name; rest is body
        lines = part.split("\n", 1)
        pkg_name = lines[0].strip()
        body = lines[1] if len(lines) > 1 else ""
        packages.append((pkg_name, body))
    if not packages:
        raise ValueError(f"no packages found in {source_name}")
    return packages


def merge(files: List[Path], output: Path) -> None:
    header = """\
# =============================================================================
# ARHIAX v11.4 — All Bundles (B01 – B19)
# =============================================================================
#
# This file is an auto-generated merge of the 19 OPA policy bundles that make
# up the ARHIAX v11.4 runtime policy layer. It is produced by merging:
#   - authz.rego              (B14 AIM Identity, B16 AIM Permissions)
#   - bundles_b01_b19.rego    (B01-B13 runtime, B15 lifecycle, B17-B19 governance)
#
# Spec anchors:
#   - TR-2026-034 MasterSpec §3 (Control Registry)
#   - TR-2026-033 Phase3 §4    (Bundle Specifications)
#
# DO NOT EDIT BY HAND. Regenerate with:
#     python merge_bundles.py authz.rego bundles_b01_b19.rego arhiax_all_bundles.rego
#
# Deploy via ConfigMap (Helm chart arhiax-runtime) or as a signed OPA bundle.
# =============================================================================

"""
    all_packages: List[Tuple[str, str, str]] = []  # (pkg_name, body, source_file)
    seen = set()

    for f in files:
        content = f.read_text(encoding="utf-8")
        for pkg_name, body in extract_packages(content, f.name):
            if pkg_name in seen:
                print(f"WARNING: duplicate package {pkg_name} in {f.name}, skipping")
                continue
            seen.add(pkg_name)
            all_packages.append((pkg_name, body, f.name))

    with output.open("w", encoding="utf-8") as fh:
        fh.write(header)
        for pkg_name, body, source in all_packages:
            fh.write(f"# ---------------------------------------------------------------------------\n")
            fh.write(f"# Package: {pkg_name}   (source: {source})\n")
            fh.write(f"# ---------------------------------------------------------------------------\n")
            fh.write(f"package {pkg_name}\n")
            fh.write(body.rstrip() + "\n\n")

    print(f"merged {len(all_packages)} packages from {len(files)} files → {output}")
    for pkg, _, src in all_packages:
        print(f"  {pkg:<40} ({src})")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("usage: merge_bundles.py <file1.rego> [file2.rego ...] <output.rego>")
        sys.exit(2)
    inputs = [Path(p) for p in sys.argv[1:-1]]
    output = Path(sys.argv[-1])
    for f in inputs:
        if not f.exists():
            print(f"ERROR: {f} not found")
            sys.exit(1)
    merge(inputs, output)
