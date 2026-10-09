"""Deterministic dependency fixture patcher. No model, credentials or external writes."""
import difflib
from pathlib import Path

PATCHED = '''"""Vendored teaching fixture, version 1.0.1 (not a published package/CVE)."""
VERSION = "1.0.1"

def normalize_slug(value):
    normalized = value.strip().lower()
    if not normalized or "/" in normalized or "\\\\" in normalized:
        raise ValueError("slug must be a nonempty identifier without path separators")
    return normalized
'''
def patch(workspace):
    target = Path(workspace) / "slug_dependency.py"
    before = target.read_text()
    target.write_text(PATCHED)
    return "".join(difflib.unified_diff(before.splitlines(True), PATCHED.splitlines(True),
        fromfile="a/slug_dependency.py", tofile="b/slug_dependency.py"))

