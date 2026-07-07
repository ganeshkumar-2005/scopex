"""
reports/json_report.py — Structured JSON report generator for ScopeX v2.
Designed for CI/CD pipeline integration — outputs to file and/or stdout.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from loguru import logger


def generate_json_report(
    scan_result_dict: dict,
    output_file: Optional[str] = None,
    to_stdout: bool = False,
) -> str:
    """
    Generate a structured JSON report from a ScanResult dict.

    Args:
        scan_result_dict: The dict from ScanResult.to_dict()
        output_file:      Optional file path to write to
        to_stdout:        If True, also print to stdout (for CI/CD pipelines)

    Returns:
        JSON string of the report
    """
    log = logger.bind(scanner="JSONReport")

    report = {
        "scopex_version": "2.0.0",
        "report_type": "web_vapt",
        **scan_result_dict,
    }

    json_output = json.dumps(report, indent=2, default=str)

    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_output)
        log.info(f"JSON report saved: {output_path}")

    if to_stdout:
        print(json_output)

    return json_output
