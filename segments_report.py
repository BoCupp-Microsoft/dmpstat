#!/usr/bin/env python3
"""Generate an HTML report from the output of `segments --summary`.

Usage:
    segments.exe <dump> --summary [--all] | python segments_report.py [-o report.html]
    python segments_report.py -i summary.txt -o report.html

The script reads the table emitted by `segments --summary` (pipe-separated
columns:  State | Type | Prot | AllocProt | Regions | Total Size | Bytes),
classifies each row, and emits an HTML report based on
`segments_report_template.html` next to this script.

To customise the per-classification explanations, edit
segments_report_template.html - no code change required.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html as _html
import re
import sys
from pathlib import Path
from typing import Iterable, NamedTuple


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

class Row(NamedTuple):
    state: str
    type_: str
    prot: str
    alloc_prot: str
    regions: int
    total_size: str
    bytes_: int


_HEADER_RE = re.compile(r"^\s*State\s*\|\s*Type\s*\|\s*Prot\s*\|", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^\s*-+\s*\|")
_FOOTER_RE = re.compile(
    r"^\s*Distinct combinations:\s*\d+\s+Regions:\s*\d+\s+Total:.*$",
    re.IGNORECASE,
)


def parse_summary(text: str) -> tuple[list[Row], str]:
    """Parse `segments --summary` output.

    Returns (rows, footer_line).
    """
    rows: list[Row] = []
    footer = ""
    in_table = False

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _HEADER_RE.match(line):
            in_table = True
            continue
        if _SEPARATOR_RE.match(line):
            continue
        if _FOOTER_RE.match(line):
            footer = line.strip()
            in_table = False
            continue
        if not in_table:
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 7:
            # Unrecognised line inside the table; skip rather than crash.
            continue
        try:
            regions = int(parts[4])
            bytes_ = int(parts[6])
        except ValueError:
            continue
        rows.append(Row(
            state=parts[0],
            type_=parts[1],
            prot=parts[2],
            alloc_prot=parts[3],
            regions=regions,
            total_size=parts[5],
            bytes_=bytes_,
        ))

    return rows, footer


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def _strip_suffixes(prot: str) -> tuple[str, bool]:
    """Return (base_protection, has_guard) for a value like 'RW-+G'."""
    has_guard = "+G" in prot
    base = prot.split("+", 1)[0]
    return base, has_guard


def classify(row: Row) -> str:
    """Map a row to one of the keys defined in the HTML template."""
    state = row.state.upper()
    type_ = row.type_.upper()
    base_prot, has_guard = _strip_suffixes(row.prot)

    if state == "FREE":
        return "free"

    if state == "RESERVE":
        if type_ == "PRIVATE": return "reserve-private"
        if type_ == "MAPPED":  return "reserve-mapped"
        if type_ == "IMAGE":   return "reserve-image"
        return "reserve-other"

    if state != "COMMIT":
        return "unknown"

    if type_ == "IMAGE":
        if base_prot == "R-X": return "image-text"
        if base_prot == "R--": return "image-rodata"
        if base_prot == "RWC": return "image-data-cow"
        if base_prot == "RW-": return "image-data-written"
        if base_prot == "RWX": return "image-rwx"
        return "image-other"

    if type_ == "MAPPED":
        if base_prot == "R--":  return "mapped-readonly"
        if base_prot == "RW-":  return "mapped-readwrite"
        if base_prot == "R-X":  return "mapped-exec"
        if base_prot in ("---", "-"): return "mapped-noaccess"
        return "mapped-other"

    if type_ == "PRIVATE":
        if has_guard:           return "private-guard"
        if base_prot == "RW-":  return "private-rw"
        if base_prot == "R-X":  return "private-rx"
        if base_prot == "RWX":  return "private-rwx"
        if base_prot == "R--":  return "private-readonly"
        if base_prot == "---":  return "private-noaccess"
        return "private-other"

    return "unknown"


def pagefile_backed(row: Row) -> tuple[str, str]:
    """Decide whether a (State, Type, Prot) combination is charged against
    the system commit limit (i.e. backed by the pagefile if not resident).

    Returns (label, reason).  Label is one of "Yes", "No", "Maybe".
    """
    state = row.state.upper()
    type_ = row.type_.upper()
    base_prot, _ = _strip_suffixes(row.prot)

    if state == "FREE":
        return ("No", "Free address space - no commit charge.")
    if state == "RESERVE":
        return ("No", "Reserved but not committed - no commit charge.")
    if state != "COMMIT":
        return ("Maybe", "Unrecognised state.")

    if type_ == "PRIVATE":
        return ("Yes", "Committed private memory is always charged against the commit limit.")

    if type_ == "IMAGE":
        # Image pages: only privatized (written) pages cost commit; clean
        # pages page back to the file.
        if base_prot in ("RW-", "RWX"):
            return ("Yes", "Privatized image pages are pagefile-backed (relocations, IAT writes, written .data).")
        if base_prot == "RWC":
            return ("No", "Copy-on-write but not yet written - still shared with the on-disk image.")
        # R-X, R--, --X, etc.
        return ("No", "Read-only / executable image pages are file-backed, not charged.")

    if type_ == "MAPPED":
        # MAPPED could be a file-backed view (no commit charge) or a
        # pagefile-backed section used for shared memory (charged).  Not
        # distinguishable from MEMORY_BASIC_INFORMATION alone.
        if base_prot in ("---", "-"):
            return ("No", "Inaccessible mapped pages are not charged.")
        return ("Maybe",
                "Could be a file-backed view (not charged) or a pagefile-backed shared section (charged); "
                "cannot be distinguished from this dump's metadata alone.")

    return ("Maybe", "Unrecognised type.")


# --------------------------------------------------------------------------- #
# Template handling
# --------------------------------------------------------------------------- #

# Parse  <template data-key="..." data-label="..." data-tag="..."> ... </template>
_TEMPLATE_BLOCK_RE = re.compile(
    r'<template\s+([^>]*?)>\s*(.*?)\s*</template>',
    re.DOTALL | re.IGNORECASE,
)
_HELP_BLOCK_RE = re.compile(
    r'<template\s+data-help[^>]*>\s*(.*?)\s*</template>',
    re.DOTALL | re.IGNORECASE,
)
_ATTR_RE = re.compile(r'([\w-]+)\s*=\s*"([^"]*)"')


class Explanation(NamedTuple):
    label: str
    tag: str   # info / ok / warn / bad
    body: str  # raw HTML


def parse_explanations(template_html: str) -> dict[str, Explanation]:
    out: dict[str, Explanation] = {}
    for m in _TEMPLATE_BLOCK_RE.finditer(template_html):
        attrs = dict(_ATTR_RE.findall(m.group(1)))
        key = attrs.get("data-key")
        if not key:
            continue
        out[key] = Explanation(
            label=attrs.get("data-label", key),
            tag=attrs.get("data-tag", "info"),
            body=m.group(2).strip(),
        )
    return out


def parse_help(template_html: str) -> str:
    """Extract the inner HTML of the <template data-help> block."""
    m = _HELP_BLOCK_RE.search(template_html)
    return m.group(1).strip() if m else "<p>(No help content found in template.)</p>"


def strip_template_blocks(template_html: str) -> str:
    """Remove every <template data-key="..."> block from the source HTML
    so they don't appear (or get reparsed) inside the rendered document."""
    return _TEMPLATE_BLOCK_RE.sub("", template_html)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_row(row: Row, explanation: Explanation, original_index: int) -> str:
    e = _html.escape
    key = classify(row)
    pf_label, pf_reason = pagefile_backed(row)
    pf_class = {"Yes": "yes", "No": "no", "Maybe": "maybe"}.get(pf_label, "maybe")
    label_html = (
        f'<span class="tag {e(explanation.tag)}">{e(explanation.tag)}</span>'
        f'{e(explanation.label)}'
    )
    return (
        f'<details class="row" data-key="{e(key)}"'
        f' data-original-index="{original_index}"'
        f' data-state="{e(row.state)}"'
        f' data-type="{e(row.type_)}"'
        f' data-prot="{e(row.prot)}"'
        f' data-allocprot="{e(row.alloc_prot)}"'
        f' data-regions="{row.regions}"'
        f' data-bytes="{row.bytes_}"'
        f' data-classification="{e(explanation.label)}"'
        f' data-severity="{e(explanation.tag)}"'
        f' data-pagefile="{pf_class}">'
        f'<summary><span class="cols">'
        f'<span class="mono">{e(row.state)}</span>'
        f'<span class="mono">{e(row.type_)}</span>'
        f'<span class="mono">{e(row.prot)}</span>'
        f'<span class="mono">{e(row.alloc_prot)}</span>'
        f'<span class="num mono">{row.regions:,}</span>'
        f'<span class="num mono">{e(row.total_size)}</span>'
        f'<span class="pf pf-{pf_class}" title="{e(pf_reason)}">{e(pf_label)}</span>'
        f'<span class="label">{label_html}</span>'
        f'</span></summary>'
        f'<div class="explanation">{explanation.body}</div>'
        f'</details>\n'
    )


def render_report(
    template_html: str,
    rows: Iterable[Row],
    footer: str,
    title: str,
) -> str:
    explanations = parse_explanations(template_html)
    help_html = parse_help(template_html)
    fallback = explanations.get("unknown") or Explanation(
        label="Unclassified", tag="info", body="<p>No explanation available.</p>"
    )

    rendered_rows = "".join(
        render_row(r, explanations.get(classify(r), fallback), i)
        for i, r in enumerate(rows)
    )

    body = strip_template_blocks(template_html)
    body = body.replace("{{TITLE}}", _html.escape(title))
    body = body.replace(
        "{{GENERATED}}",
        _dt.datetime.now().isoformat(timespec="seconds"),
    )
    body = body.replace("{{ROWS}}", rendered_rows)
    body = body.replace("{{FOOTER}}", _html.escape(footer or "(no footer)"))
    body = body.replace("{{HELP}}", help_html)
    return body


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate an HTML report from `segments --summary` output."
    )
    parser.add_argument(
        "-i", "--input", type=Path, default=None,
        help="Read summary text from a file (default: stdin).",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("segments_report.html"),
        help="Output HTML file (default: segments_report.html).",
    )
    parser.add_argument(
        "-t", "--template", type=Path,
        default=Path(__file__).resolve().with_name("segments_report_template.html"),
        help="HTML template path.",
    )
    parser.add_argument(
        "--title", default=None,
        help="Title to show in the report header (default: input file path or 'stdin').",
    )
    args = parser.parse_args(argv)

    if args.input is not None:
        text = args.input.read_text(encoding="utf-8", errors="replace")
        title = args.title or str(args.input)
    else:
        text = sys.stdin.read()
        title = args.title or "stdin"

    rows, footer = parse_summary(text)
    if not rows:
        print("error: no summary rows parsed from input", file=sys.stderr)
        return 2

    template = args.template.read_text(encoding="utf-8")
    html = render_report(template, rows, footer, title)
    args.output.write_text(html, encoding="utf-8")

    print(
        f"Wrote {args.output} ({len(rows)} rows).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
