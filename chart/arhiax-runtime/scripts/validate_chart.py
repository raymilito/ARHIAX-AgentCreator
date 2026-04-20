#!/usr/bin/env python3
"""
ARHIAX Runtime - structural chart validator.

This is NOT a replacement for `helm lint`. It validates what can be validated
without a Helm binary:
  1. YAML parseability of Chart.yaml / values.yaml (parent and subcharts)
  2. Balance of {{ }} delimiters and if/with/range vs end blocks
  3. Named templates referenced vs defined (per-chart scope)
  4. .Values.<path> references vs the actual values.yaml schema
  5. Symbolic render: substitute {{...}} with placeholders and parse result as YAML

Exit codes:
  0  all checks passed
  1  one or more checks failed
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

CHART_ROOT = Path(__file__).resolve().parent.parent
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
BOLD = "\033[1m"

errors: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)
    print(f"{RED}[FAIL]{RESET} {msg}")


def warn(msg: str) -> None:
    warnings.append(msg)
    print(f"{YELLOW}[WARN]{RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{GREEN}[OK]{RESET}   {msg}")


def section(msg: str) -> None:
    print(f"\n{BOLD}{BLUE}== {msg} =={RESET}")


# -----------------------------------------------------------------------------
# 1. YAML parseability of static files
# -----------------------------------------------------------------------------
def check_yaml_parse() -> dict:
    section("1. YAML parseability of static files")
    result = {}
    targets = [
        CHART_ROOT / "Chart.yaml",
        CHART_ROOT / "values.yaml",
        CHART_ROOT / "charts" / "correlator" / "Chart.yaml",
        CHART_ROOT / "charts" / "correlator" / "values.yaml",
    ]
    for t in targets:
        if not t.exists():
            err(f"missing file: {t.relative_to(CHART_ROOT)}")
            continue
        try:
            with open(t) as f:
                data = yaml.safe_load(f)
            result[str(t.relative_to(CHART_ROOT))] = data
            ok(f"parsed {t.relative_to(CHART_ROOT)}")
        except yaml.YAMLError as e:
            err(f"YAML parse error in {t.relative_to(CHART_ROOT)}: {e}")
    return result


# -----------------------------------------------------------------------------
# 2. Delimiter and block balance
# -----------------------------------------------------------------------------
BLOCK_OPEN = re.compile(r"\{\{-?\s*(if|with|range|define|block)\b")
BLOCK_CLOSE = re.compile(r"\{\{-?\s*end\s*-?\}\}")
ELSE_TOK = re.compile(r"\{\{-?\s*else\b")
COMPLETE_EXPR = re.compile(r"\{\{-?.*?-?\}\}", re.DOTALL)


def check_delimiter_balance(template_files: list[Path]) -> None:
    section("2. Delimiter and block balance")
    for tf in template_files:
        content = tf.read_text()
        # Strip all complete {{...}} expressions; anything remaining is
        # literal text. Orphan {{ in residual = unclosed expression (error).
        # Orphan }} in residual = literal text (e.g., JSON example in NOTES.txt).
        residual = COMPLETE_EXPR.sub("", content)
        orphan_open = residual.count("{{")
        if orphan_open > 0:
            err(
                f"{tf.relative_to(CHART_ROOT)}: {orphan_open} unclosed "
                f"template expression(s) (orphan {{{{)"
            )
            continue
        # Count block opens vs ends on the original content
        opens = len(BLOCK_OPEN.findall(content))
        closes = len(BLOCK_CLOSE.findall(content))
        if opens != closes:
            err(
                f"{tf.relative_to(CHART_ROOT)}: unbalanced blocks "
                f"(if/with/range/define: {opens}, end: {closes})"
            )
            continue
        ok(f"{tf.relative_to(CHART_ROOT)} delimiters balanced")


# -----------------------------------------------------------------------------
# 3. Named templates: referenced vs defined
# -----------------------------------------------------------------------------
DEFINE_RE = re.compile(r'\{\{-?\s*define\s+"([^"]+)"\s*-?\}\}')
INCLUDE_RE = re.compile(r'\{\{-?\s*(?:include|template)\s+"([^"]+)"')


def check_named_templates(parent_templates: list[Path], subchart_templates: dict[str, list[Path]]) -> None:
    section("3. Named templates referenced vs defined")

    def collect(files: list[Path]) -> tuple[set[str], set[tuple[Path, str]]]:
        defined: set[str] = set()
        referenced: set[tuple[Path, str]] = set()
        for f in files:
            text = f.read_text()
            for m in DEFINE_RE.finditer(text):
                defined.add(m.group(1))
            for m in INCLUDE_RE.finditer(text):
                referenced.add((f, m.group(1)))
        return defined, referenced

    # Parent chart has its own namespace of named templates
    parent_defined, parent_refs = collect(parent_templates)
    # Helm provides some built-in templates we shouldn't flag
    builtins = {
        "default",  # not a template but sometimes aliased
    }
    missing = [
        (f, name)
        for f, name in parent_refs
        if name not in parent_defined and name not in builtins
    ]
    if missing:
        for f, name in missing:
            err(
                f"{f.relative_to(CHART_ROOT)}: references undefined template "
                f'"{name}" (parent chart namespace)'
            )
    else:
        ok(f"parent chart: all {len(parent_refs)} template references resolve ({len(parent_defined)} defined)")

    # Subcharts have isolated namespaces
    for name, files in subchart_templates.items():
        sub_defined, sub_refs = collect(files)
        missing = [
            (f, n)
            for f, n in sub_refs
            if n not in sub_defined and n not in builtins
        ]
        if missing:
            for f, n in missing:
                err(
                    f"{f.relative_to(CHART_ROOT)}: references undefined template "
                    f'"{n}" (subchart {name} namespace)'
                )
        else:
            ok(
                f"subchart {name}: all {len(sub_refs)} template references "
                f"resolve ({len(sub_defined)} defined)"
            )


# -----------------------------------------------------------------------------
# 4. .Values.<path> references vs values.yaml schema
# -----------------------------------------------------------------------------
VALUES_REF = re.compile(r"\.Values\.([a-zA-Z_][a-zA-Z0-9_.]*)")


def walk_keys(d: dict, prefix: str = "") -> set[str]:
    keys = set()
    if not isinstance(d, dict):
        return keys
    for k, v in d.items():
        path = f"{prefix}.{k}" if prefix else k
        keys.add(path)
        if isinstance(v, dict):
            keys |= walk_keys(v, path)
    return keys


def check_values_refs(
    parent_templates: list[Path],
    parent_values: dict,
    subchart_templates: dict[str, list[Path]],
    subchart_values: dict[str, dict],
) -> None:
    section("4. .Values references vs schema")

    parent_keys = walk_keys(parent_values or {})

    # Parent templates can reference any key under .Values (parent) AND any
    # subchart's top-level alias (e.g., .Values.correlator.enabled)
    parent_refs = set()
    for f in parent_templates:
        text = f.read_text()
        for m in VALUES_REF.finditer(text):
            parent_refs.add((f, m.group(1)))

    # Keys that are valid even if not in values.yaml (computed, built-in,
    # or expected to come from user overrides for dynamic config)
    parent_allowlist = {
        # extraEnv/Volumes/etc that are lists users populate
    }

    missing_parent = []
    for f, ref in parent_refs:
        # Check exact match or any prefix match (e.g., gateway.service.port matches gateway.service)
        parts = ref.split(".")
        found = False
        for i in range(len(parts), 0, -1):
            candidate = ".".join(parts[:i])
            if candidate in parent_keys:
                found = True
                break
        if not found and ref not in parent_allowlist:
            missing_parent.append((f, ref))

    if missing_parent:
        # Deduplicate by ref
        seen = set()
        for f, ref in missing_parent:
            if ref in seen:
                continue
            seen.add(ref)
            err(
                f"{f.relative_to(CHART_ROOT)}: .Values.{ref} has no match in parent values.yaml"
            )
    else:
        ok(f"parent chart: all {len(parent_refs)} .Values references resolve")

    # Subcharts: refs must match the subchart's own values.yaml
    for name, files in subchart_templates.items():
        sub_keys = walk_keys(subchart_values.get(name, {}) or {})
        sub_refs = set()
        for f in files:
            text = f.read_text()
            for m in VALUES_REF.finditer(text):
                sub_refs.add((f, m.group(1)))
        missing = []
        for f, ref in sub_refs:
            parts = ref.split(".")
            found = False
            for i in range(len(parts), 0, -1):
                candidate = ".".join(parts[:i])
                if candidate in sub_keys:
                    found = True
                    break
            if not found:
                missing.append((f, ref))
        if missing:
            seen = set()
            for f, ref in missing:
                if ref in seen:
                    continue
                seen.add(ref)
                err(
                    f"{f.relative_to(CHART_ROOT)}: .Values.{ref} has no match in subchart {name} values.yaml"
                )
        else:
            ok(f"subchart {name}: all {len(sub_refs)} .Values references resolve")


# -----------------------------------------------------------------------------
# 5. Symbolic render + YAML parse
# -----------------------------------------------------------------------------
# Replace any {{ ... }} expression with a deterministic placeholder so the
# resulting text can be parsed as YAML. This catches indentation disasters.
TEMPLATE_EXPR = re.compile(r"\{\{-?.*?-?\}\}", re.DOTALL)


def symbolic_render(text: str) -> str:
    # Strip leading {{- and trailing -}} whitespace trimming semantics: replace
    # the whole expression with a safe scalar. We need to be context-aware:
    # - If the expression is the whole line (possibly with leading whitespace),
    #   replace with empty line (preserves indentation for surrounding block).
    # - If inline inside a YAML value, replace with "PLACEHOLDER".
    lines = text.split("\n")
    out = []
    for line in lines:
        stripped = line.strip()
        # Whole-line template directive: replace with empty
        if stripped.startswith("{{") and stripped.endswith("}}"):
            out.append("")
            continue
        # Inline: replace {{...}} with PLACEHOLDER
        replaced = TEMPLATE_EXPR.sub("PLACEHOLDER", line)
        out.append(replaced)
    return "\n".join(out)


def check_symbolic_render(template_files: list[Path]) -> None:
    section("5. Symbolic render + YAML parse")
    for tf in template_files:
        # Skip helper files and NOTES.txt (neither is a K8s manifest)
        if tf.name.endswith(".tpl") or tf.name == "NOTES.txt":
            continue
        text = tf.read_text()
        rendered = symbolic_render(text)
        try:
            docs = list(yaml.safe_load_all(rendered))
            # Filter None docs (empty documents from conditional rendering)
            real_docs = [d for d in docs if d is not None]
            ok(
                f"{tf.relative_to(CHART_ROOT)} symbolic render parsed "
                f"({len(real_docs)} doc(s))"
            )
        except yaml.YAMLError as e:
            err(f"{tf.relative_to(CHART_ROOT)} symbolic render YAML error: {e}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main() -> int:
    print(f"{BOLD}ARHIAX Runtime chart structural validator{RESET}")
    print(f"Chart root: {CHART_ROOT}")

    # Parse static files
    parsed = check_yaml_parse()
    parent_values = parsed.get("values.yaml", {}) or {}
    subchart_values = {
        "correlator": parsed.get("charts/correlator/values.yaml", {}) or {},
    }

    # Gather templates
    parent_template_dir = CHART_ROOT / "templates"
    parent_templates = sorted(parent_template_dir.glob("*"))
    parent_templates = [p for p in parent_templates if p.is_file()]

    subchart_templates = {}
    for sub in (CHART_ROOT / "charts").glob("*"):
        if sub.is_dir():
            tdir = sub / "templates"
            if tdir.exists():
                subchart_templates[sub.name] = [
                    p for p in sorted(tdir.glob("*")) if p.is_file()
                ]

    all_templates = list(parent_templates)
    for files in subchart_templates.values():
        all_templates.extend(files)

    check_delimiter_balance(all_templates)
    check_named_templates(parent_templates, subchart_templates)
    check_values_refs(
        parent_templates, parent_values, subchart_templates, subchart_values
    )
    check_symbolic_render(all_templates)

    print()
    if errors:
        print(f"{RED}{BOLD}FAILED: {len(errors)} error(s), {len(warnings)} warning(s){RESET}")
        return 1
    print(f"{GREEN}{BOLD}PASSED: 0 errors, {len(warnings)} warning(s){RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
