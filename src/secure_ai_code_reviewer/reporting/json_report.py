from __future__ import annotations

import json
from pathlib import Path

from ..models import Report


def write_json_report(report: Report, output: Path) -> None:
    output.write_text(json.dumps(report.model_dump(), indent=2))
