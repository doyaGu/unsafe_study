#!/usr/bin/env python3
"""
summarize_geiger.py — Parse cargo-geiger JSON and produce Markdown hotspot tables.

Usage:
  python scripts/summarize_geiger.py geiger_reports/
  python scripts/summarize_geiger.py geiger_reports/httparse.json
"""

import json
import sys
from pathlib import Path
from collections import defaultdict


def parse_geiger_json(path: Path) -> dict:
    """Parse a cargo-geiger JSON report and extract unsafe counts per package."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    packages = {}

    # cargo-geiger JSON structure: "packages" array with unsafety counts
    for pkg in data.get("packages", []):
        pkg_id = pkg.get("id", {})
        name = pkg_id.get("name", "unknown") if isinstance(pkg_id, dict) else str(pkg_id)

        unsafety = pkg.get("unsafety", {})
        used = unsafety.get("used", {})
        unused = unsafety.get("unused", {})

        def count_category(cat):
            return {
                "functions": cat.get("functions", {}).get("unsafe_", 0),
                "exprs": cat.get("exprs", {}).get("unsafe_", 0),
                "impls": cat.get("impls", {}).get("unsafe_", 0),
            }

        used_counts = count_category(used)
        unused_counts = count_category(unused)

        total = sum(used_counts.values()) + sum(unused_counts.values())
        if total > 0:
            packages[name] = {
                "used": used_counts,
                "unused": unused_counts,
                "total": total,
            }

    return packages


def format_table(crate_name: str, packages: dict) -> list[str]:
    """Format a Markdown table for one crate's geiger results, ranked by total unsafe."""
    ranked = sorted(packages.items(), key=lambda kv: kv[1]["total"], reverse=True)

    lines = []
    lines.append(f"### {crate_name}")
    lines.append("")
    lines.append("| Package | unsafe fn (used) | unsafe expr (used) | unsafe impl (used) | Total |")
    lines.append("|---------|-----------------|-------------------|-------------------|-------|")

    for pkg_name, counts in ranked:
        u = counts["used"]
        lines.append(
            f"| {pkg_name} | {u['functions']} | {u['exprs']} | {u['impls']} | {counts['total']} |"
        )

    lines.append("")
    return lines


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(1)

    target = Path(sys.argv[1])
    files = []

    if target.is_dir():
        files = sorted(target.glob("*.json"))
    elif target.is_file() and target.suffix == ".json":
        files = [target]
    else:
        print(f"Error: {target} is not a JSON file or directory", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("No .json files found.", file=sys.stderr)
        sys.exit(1)

    all_lines = ["# Cargo-Geiger Hotspot Summary", ""]

    for json_file in files:
        crate_name = json_file.stem
        try:
            packages = parse_geiger_json(json_file)
            if packages:
                all_lines.extend(format_table(crate_name, packages))
            else:
                all_lines.append(f"### {crate_name}")
                all_lines.append("")
                all_lines.append("No unsafe usage detected.")
                all_lines.append("")
        except (json.JSONDecodeError, KeyError) as e:
            all_lines.append(f"### {crate_name}")
            all_lines.append("")
            all_lines.append(f"Error parsing: {e}")
            all_lines.append("")

    output_path = Path(sys.argv[1])
    if output_path.is_dir():
        summary_path = output_path / "SUMMARY.md"
    else:
        summary_path = output_path.parent / "SUMMARY.md"

    summary_path.write_text("\n".join(all_lines), encoding="utf-8")
    print(f"Summary written to {summary_path}")

    # Also print to stdout
    print("\n".join(all_lines))


if __name__ == "__main__":
    main()
