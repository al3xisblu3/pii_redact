# pii_redact

Batch-redact PII (emails, US phone numbers, SSN-like patterns, and custom names) from text-based PDFs. Produces redacted PDFs with opaque boxes placed exactly over matched text and a CSV redaction log.

## MVP Features
- Digital (text-extractable) PDFs only; scanned PDFs are skipped and logged as `needs_ocr=1`.
- Detects:
  - Emails
  - US phone numbers
  - SSN-like patterns (###-##-####)
  - Optional custom names list
- Outputs a new redacted PDF per input with precise rectangles.
- Exports `redaction_log.csv` with: file, page, category, match_text (masked), bbox, timestamp, needs_ocr.

## Install (editable)
```
pip install -e .
```

## Usage
```
pii_redact \
  --input <path_to_pdf_or_folder> \
  --output <output_dir> \
  [--names <path_to_names_txt>] \
  [--log <path_to_csv_log>] \
  [--mask-log] \
  [--overwrite] \
  [--category email phone ssn name] \
  [--min-font 8.0] \
  [--verbose]
```

- `--input`: single PDF file or a directory of PDFs.
- `--output`: output directory (created if needed). Output file name is `<basename>.redacted.pdf`.
- `--names`: newline-delimited names to redact (case-insensitive, word-boundary).
- `--log`: CSV log path (defaults to `<output>/redaction_log.csv`). Appends unless `--overwrite`.
- `--mask-log`: mask matched text in the CSV (emails/phones/SSN/names masked appropriately).
- `--overwrite`: allow overwriting redacted PDFs and recreate the log file.
- `--category`: restrict to a subset of categories (default all).
- `--min-font`: ignore spans smaller than this font size (approximate, based on span sizes from PyMuPDF).
- `--verbose`: print progress and a final summary.

## Notes
- This tool uses PyMuPDF to detect text locations and add redact annotations, then applies them to remove the underlying text.
- For scanned PDFs without a text layer, the tool will not perform OCR in the MVP and will record `needs_ocr=1` in the log.
 - Overlapping matches are merged into a single rectangle to avoid stacked boxes. Each match is still logged.

## Output Conventions
- Output filename: `<original_basename>.redacted.pdf` in `--output`.
- CSV columns: `file,page,category,match_text,bbox,timestamp,needs_ocr`.
- Final summary printed with `--verbose`.

## Development
- Python 3.10+
- PyMuPDF (fitz)
- csv

## Quickstart
```
pip install -e .
pii_redact --input sample_pdfs --output redacted_out --verbose --mask-log
```
