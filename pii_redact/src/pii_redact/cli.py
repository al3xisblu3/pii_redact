from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from .pdf_redactor import process_inputs


def _load_names_file(path: Optional[Path]) -> Optional[List[str]]:
    if not path:
        return None
    if not path.exists():
        raise FileNotFoundError(f"Names file not found: {path}")
    names: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            name = line.strip()
            if name:
                names.append(name)
    return names


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pii_redact",
        description=(
            "Batch-redact PII (emails, US phone numbers, SSN-like patterns, and optional custom names) "
            "from text PDFs with precise overlays and CSV logging."
        ),
    )
    p.add_argument("--input", required=True, help="Path to a single PDF or a directory containing PDFs")
    p.add_argument("--output", required=True, help="Output directory for redacted PDFs (created if missing)")
    p.add_argument("--names", required=False, help="Optional path to newline-delimited names list to redact")
    p.add_argument(
        "--log",
        required=False,
        help="CSV log path (defaults to <output>/redaction_log.csv)",
    )
    p.add_argument("--mask-log", action="store_true", help="Mask matched text in CSV log instead of full value")
    p.add_argument("--overwrite", action="store_true", help="Allow overwriting output files and recreate log file")
    p.add_argument(
        "--category",
        nargs="+",
        choices=["email", "phone", "ssn", "name"],
        help="Restrict detection to these categories (default: all)",
    )
    p.add_argument("--min-font", type=float, default=0.0, help="Ignore text smaller than this font size")
    p.add_argument("--verbose", action="store_true", help="Print progress")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_dir = Path(args.output)
    names_path = Path(args.names) if args.names else None

    if not input_path.exists():
        parser.error(f"Input path does not exist: {input_path}")

    if args.log:
        csv_log_path = Path(args.log)
    else:
        csv_log_path = output_dir / "redaction_log.csv"

    names = _load_names_file(names_path)

    process_inputs(
        input_path=input_path,
        output_dir=output_dir,
        csv_log_path=csv_log_path,
        names=names,
        categories=args.category,
        min_font=args.min_font,
        mask_log=args.mask_log,
        overwrite=args.overwrite,
        verbose=args.verbose,
    )

    if args.verbose:
        print(f"Completed. Log: {csv_log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
