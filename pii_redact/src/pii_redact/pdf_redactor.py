from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import fitz  # PyMuPDF

from .detectors import detect_pii, compile_name_patterns, mask_for_log


@dataclass
class RedactionMatch:
    category: str
    text: str
    bbox: Tuple[float, float, float, float]
    page_index: int  # 0-based


class PDFRedactor:
    def __init__(self, names: Optional[Iterable[str]] = None, categories: Optional[List[str]] = None, min_font: float = 0.0, verbose: bool = False) -> None:
        self.name_patterns = compile_name_patterns(names)
        self.categories = set(categories) if categories else None
        self.min_font = float(min_font or 0.0)
        self.verbose = verbose

    def _is_scanned_pdf(self, doc: fitz.Document) -> bool:
        # Heuristic: if all pages have no words, assume scanned/no text layer
        for page in doc:
            words = page.get_text("words")  # list of tuples; empty if no text
            if words:
                return False
        return True

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _iter_page_matches(self, page: fitz.Page) -> List[RedactionMatch]:
        text = page.get_text("text") or ""
        pii_matches = detect_pii(text, self.name_patterns)
        if self.categories is not None:
            pii_matches = [m for m in pii_matches if m["category"] in self.categories]
        results: List[RedactionMatch] = []
        if not pii_matches:
            return results

        # Pull span information once for min-font filtering
        span_cache = page.get_text("dict")

        for m in pii_matches:
            needle = m["text"]
            # Find exact visual occurrences via search_for; collect rectangles
            # flags=0 is fine for MVP; quads=True gives tighter coverage.
            try:
                hits = page.search_for(needle, quads=True)
            except TypeError:
                # older PyMuPDF without quads kwarg
                hits = page.search_for(needle)

            if not hits:
                # Could not locate visually; skip for MVP
                continue

            for h in hits:
                # h may be Rect or Quad; normalize to Rect bbox
                if hasattr(h, "rect"):
                    r = h.rect  # type: ignore[attr-defined]
                else:
                    r = h
                bbox = (float(r.x0), float(r.y0), float(r.x1), float(r.y1))

                # Min-font filtering: if all overlapping spans are below threshold, skip
                if self.min_font > 0:
                    if not self._bbox_meets_min_font(bbox, span_cache, self.min_font):
                        continue
                results.append(
                    RedactionMatch(
                        category=m["category"],
                        text=needle,
                        bbox=bbox,
                        page_index=page.number,
                    )
                )
        return results

    def _bbox_meets_min_font(self, bbox: Tuple[float, float, float, float], span_dict: dict, min_font: float) -> bool:
        x0, y0, x1, y1 = bbox
        # span_dict structure: { blocks: [ { lines: [ { spans: [ { 'size': float, 'bbox': [x0,y0,x1,y1], 'text': str }, ... ] } ] } ] }
        try:
            blocks = span_dict.get("blocks", [])
        except Exception:
            return True  # be permissive if structure unexpected
        any_overlap = False
        for b in blocks:
            for ln in b.get("lines", []):
                for sp in ln.get("spans", []):
                    sb = sp.get("bbox", [0, 0, 0, 0])
                    sx0, sy0, sx1, sy1 = map(float, sb)
                    if not (sx1 <= x0 or sx0 >= x1 or sy1 <= y0 or sy0 >= y1):
                        any_overlap = True
                        if float(sp.get("size", 0.0)) >= min_font:
                            return True
        # If we found any overlapping spans and none met threshold, reject; if no overlaps found, allow
        return not any_overlap

    def _merge_overlapping_rects(self, rects: List[Tuple[float, float, float, float]]) -> List[Tuple[float, float, float, float]]:
        if not rects:
            return []
        # Simple iterative merge for overlapping rectangles
        merged: List[fitz.Rect] = []
        for (x0, y0, x1, y1) in rects:
            new_rect = fitz.Rect(x0, y0, x1, y1)
            merged_any = False
            for i, existing in enumerate(list(merged)):
                if new_rect.intersects(existing):
                    existing.include_rect(new_rect)
                    merged[i] = existing
                    merged_any = True
                    break
            if not merged_any:
                merged.append(new_rect)
        return [(float(r.x0), float(r.y0), float(r.x1), float(r.y1)) for r in merged]

    def redact_pdf(self, input_pdf: Path, output_pdf: Path, csv_writer: csv.writer, mask_log: bool = True) -> Tuple[int, int]:
        """Redact a single PDF.

        Returns: (pages_redacted, matches_count)
        """
        doc = fitz.open(input_pdf)
        try:
            if self._is_scanned_pdf(doc):
                # Log needs_ocr and skip
                csv_writer.writerow(
                    [
                        input_pdf.name,
                        "",
                        "",
                        "",
                        "",
                        self._timestamp(),
                        1,
                    ]
                )
                return (0, 0)

            any_redactions = False
            pages_redacted = 0
            matches_count = 0
            for page in doc:
                page_matches = self._iter_page_matches(page)
                if not page_matches:
                    continue
                # Merge overlapping rects per page to avoid stacked blocks (logging still per match with merged bbox)
                merged_rects = self._merge_overlapping_rects([rm.bbox for rm in page_matches])
                for rect_bbox in merged_rects:
                    any_redactions = True
                    pages_redacted += 1
                    rect = fitz.Rect(*rect_bbox)
                    try:
                        page.add_redact_annot(rect, fill=(0, 0, 0))
                    except Exception:
                        page.add_redact_annot(rect)
                # Log each match using mask preference, but bbox reported as the merged bbox it falls into
                for rm in page_matches:
                    matches_count += 1
                    # find containing merged rect
                    chosen_bbox = rm.bbox
                    for mb in merged_rects:
                        mr = fitz.Rect(*mb)
                        if mr.contains(fitz.Rect(*rm.bbox)) or mr.intersects(fitz.Rect(*rm.bbox)):
                            chosen_bbox = mb
                            break
                    value = mask_for_log(rm.category, rm.text) if mask_log else rm.text
                    csv_writer.writerow(
                        [
                            input_pdf.name,
                            rm.page_index + 1,
                            rm.category,
                            value,
                            f"{chosen_bbox}",
                            self._timestamp(),
                            0,
                        ]
                    )

            if any_redactions:
                # Apply redactions per page to remove underlying content
                for page in doc:
                    try:
                        page.apply_redactions()
                    except Exception:
                        # If apply_redactions not available or fails, proceed to save with boxes drawn
                        pass
                doc.save(
                    output_pdf,
                    incremental=False,
                    deflate=True,
                    garbage=3,
                    clean=True,
                )
            else:
                # No changes; still write output as a copy
                doc.save(output_pdf)
            return (pages_redacted, matches_count)
        finally:
            doc.close()

def _output_path_for(input_pdf: Path, output_dir: Path) -> Path:
    base = input_pdf.stem
    return output_dir / f"{base}.redacted.pdf"


def _iter_input_pdfs(input_path: Path) -> List[Path]:
    if input_path.is_file() and input_path.suffix.lower() == ".pdf":
        return [input_path]
    if input_path.is_dir():
        return [p for p in sorted(input_path.iterdir()) if p.is_file() and p.suffix.lower() == ".pdf"]
    return []


def process_inputs(
    input_path: Path,
    output_dir: Path,
    csv_log_path: Path,
    names: Optional[Iterable[str]] = None,
    categories: Optional[List[str]] = None,
    min_font: float = 0.0,
    mask_log: bool = True,
    overwrite: bool = False,
    verbose: bool = False,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_log_path.parent.mkdir(parents=True, exist_ok=True)

    # Determine log mode
    log_exists = csv_log_path.exists()
    log_mode = "w" if overwrite or not log_exists else "a"

    redactor = PDFRedactor(names=names, categories=categories, min_font=min_font, verbose=verbose)

    pdfs = _iter_input_pdfs(input_path)
    if not pdfs:
        raise FileNotFoundError(f"No PDFs found at {input_path}")

    total_files = 0
    total_pages_redacted = 0
    total_matches = 0

    with open(csv_log_path, log_mode, newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if log_mode == "w":
            writer.writerow(["file", "page", "category", "match_text", "bbox", "timestamp", "needs_ocr"])  # header

        for in_pdf in pdfs:
            total_files += 1
            out_pdf = _output_path_for(in_pdf, output_dir)
            if out_pdf.exists() and not overwrite:
                if verbose:
                    print(f"Skipping existing output (use --overwrite): {out_pdf}")
                continue
            if verbose:
                print(f"Processing: {in_pdf}")
            pages_redacted, matches_count = redactor.redact_pdf(in_pdf, out_pdf, writer, mask_log=mask_log)
            total_pages_redacted += pages_redacted
            total_matches += matches_count

    if verbose:
        cat_info = ",".join(categories) if categories else "all"
        print(
            f"Summary: files={total_files}, pages_redacted={total_pages_redacted}, matches={total_matches}, "
            f"categories={cat_info}, min_font={min_font}"
        )
