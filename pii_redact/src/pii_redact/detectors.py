import re
from typing import Iterable, List, Optional, Pattern, Dict, Any

# Simple, pragmatic patterns for MVP
EMAIL_REGEX: Pattern[str] = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_REGEX: Pattern[str] = re.compile(
    r"\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b"
)
SSN_REGEX: Pattern[str] = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def compile_name_patterns(names: Optional[Iterable[str]]) -> List[Pattern[str]]:
    patterns: List[Pattern[str]] = []
    if not names:
        return patterns
    for n in names:
        n = n.strip()
        if not n:
            continue
        # word-boundary, ignore case
        patterns.append(re.compile(rf"\b{re.escape(n)}\b", re.IGNORECASE))
    return patterns


def detect_pii(text: str, custom_name_patterns: Optional[List[Pattern[str]]] = None) -> List[Dict[str, Any]]:
    """Detect PII in the given text and return list of matches.

    Each match: {category, text, start, end}
    """
    matches: List[Dict[str, Any]] = []

    for m in EMAIL_REGEX.finditer(text):
        matches.append({"category": "email", "text": m.group(0), "start": m.start(), "end": m.end()})

    for m in PHONE_REGEX.finditer(text):
        matches.append({"category": "phone", "text": m.group(0), "start": m.start(), "end": m.end()})

    for m in SSN_REGEX.finditer(text):
        matches.append({"category": "ssn", "text": m.group(0), "start": m.start(), "end": m.end()})

    if custom_name_patterns:
        for p in custom_name_patterns:
            for m in p.finditer(text):
                matches.append({"category": "name", "text": m.group(0), "start": m.start(), "end": m.end()})

    # Sort by start to have deterministic order
    matches.sort(key=lambda x: (x["start"], x["end"]))
    return matches


def mask_for_log(category: str, value: str) -> str:
    """Mask PII value for logging.

    - email: show first char of local part and domain TLD, mask middle
    - phone: keep last 4 digits
    - ssn: keep last 4 digits
    - name: mask all but first letter
    """
    if category == "email":
        parts = value.split("@")
        if len(parts) == 2:
            local, domain = parts
            masked_local = (local[:1] + "*" * max(0, len(local) - 1)) if local else "*"
            # Keep last domain label
            masked_domain = "***." + domain.split(".")[-1]
            return f"{masked_local}@{masked_domain}"
        return "***@***"

    if category == "phone":
        digits = re.sub(r"\D", "", value)
        return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***-***-****"

    if category == "ssn":
        digits = re.sub(r"\D", "", value)
        return f"***-**-{digits[-4:]}" if len(digits) >= 4 else "***-**-****"

    if category == "name":
        if not value:
            return "*"
        return value[:1] + "*" * (len(value) - 1)

    # default fallback
    return "***"
