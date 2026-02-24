"""Hayabusa runner for Windows event log (.evtx) analysis.

Hayabusa is a Windows event log fast forensics timeline generator and
threat hunting tool created by the Yamato Security group in Japan.
This module wraps the Hayabusa CLI to run analysis on .evtx files and
parse the resulting output.
"""

import asyncio
import csv
import io
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import structlog

logger = structlog.get_logger()

# Default Hayabusa detection rules minimum level
DEFAULT_MIN_LEVEL = "low"

# Supported output formats
OUTPUT_FORMATS = ("csv", "jsonl")


@dataclass
class HayabusaResult:
    """Parsed result from a Hayabusa analysis run.

    Attributes:
        evtx_path: Path to the analyzed .evtx file.
        output_path: Path to the raw output file produced by Hayabusa.
        output_format: Format of the output file ('csv' or 'jsonl').
        record_count: Number of detection records found.
        critical_count: Count of critical-level detections.
        high_count: Count of high-level detections.
        medium_count: Count of medium-level detections.
        low_count: Count of low-level detections.
        informational_count: Count of informational-level detections.
        returncode: Process exit code from Hayabusa.
        error: Error message if the run failed.
        records: Parsed detection records (list of dicts).
    """

    evtx_path: str = ""
    output_path: str = ""
    output_format: str = "csv"
    record_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    informational_count: int = 0
    returncode: int = -1
    error: str = ""
    records: List[Dict] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.error

    def summary(self, max_records: int = 20) -> str:
        """Return a human-readable summary of the analysis."""
        if not self.success:
            return f"❌ Hayabusa analysis failed: {self.error}"

        lines = [
            "🔍 Hayabusa Analysis Complete",
            f"📄 Source: {Path(self.evtx_path).name}",
            f"📊 Total detections: {self.record_count}",
            "",
            "Severity breakdown:",
            f"  🔴 Critical: {self.critical_count}",
            f"  🟠 High: {self.high_count}",
            f"  🟡 Medium: {self.medium_count}",
            f"  🔵 Low: {self.low_count}",
            f"  ⚪ Informational: {self.informational_count}",
        ]

        if self.records and max_records > 0:
            lines.append("")
            lines.append(f"Top detections (up to {max_records}):")
            # Sort by severity: critical > high > medium > low > info
            severity_order = {
                "critical": 0,
                "crit": 0,
                "high": 1,
                "medium": 2,
                "med": 2,
                "low": 3,
                "informational": 4,
                "info": 4,
            }
            sorted_records = sorted(
                self.records,
                key=lambda r: severity_order.get(r.get("Level", r.get("level", "info")).lower(), 5),
            )
            for record in sorted_records[:max_records]:
                level = record.get("Level", record.get("level", "?"))
                title = record.get("RuleTitle", record.get("rule_title", "Unknown"))
                timestamp = record.get("Timestamp", record.get("timestamp", ""))
                lines.append(f"  [{level}] {title} @ {timestamp}")

        lines.append("")
        lines.append(f"📁 Full results: {self.output_path}")
        return "\n".join(lines)


def _count_by_level(records: List[Dict]) -> Dict[str, int]:
    """Count records by severity level."""
    counts: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    for record in records:
        level = record.get("Level", record.get("level", "")).lower()
        if level in ("critical", "crit"):
            counts["critical"] += 1
        elif level == "high":
            counts["high"] += 1
        elif level in ("medium", "med"):
            counts["medium"] += 1
        elif level == "low":
            counts["low"] += 1
        elif level in ("informational", "info"):
            counts["informational"] += 1
    return counts


def parse_csv_output(csv_text: str) -> List[Dict]:
    """Parse Hayabusa CSV output into a list of record dicts."""
    records = []
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        records.append(dict(row))
    return records


def parse_jsonl_output(jsonl_text: str) -> List[Dict]:
    """Parse Hayabusa JSONL output into a list of record dicts."""
    records = []
    for line in jsonl_text.strip().splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def find_hayabusa_binary(custom_path: Optional[str] = None) -> Optional[str]:
    """Locate the Hayabusa binary.

    Checks (in order):
    1. Custom path from plugin config
    2. 'hayabusa' on system PATH
    """
    if custom_path:
        p = Path(custom_path)
        if p.is_file():
            return str(p)
    return shutil.which("hayabusa")


async def run_hayabusa(
    evtx_path: str,
    output_dir: str,
    hayabusa_path: Optional[str] = None,
    min_level: str = DEFAULT_MIN_LEVEL,
    output_format: str = "csv",
    extra_args: Optional[List[str]] = None,
) -> HayabusaResult:
    """Run Hayabusa analysis on an .evtx file.

    Args:
        evtx_path: Path to the .evtx file to analyze.
        output_dir: Directory where output files will be written.
        hayabusa_path: Optional explicit path to the Hayabusa binary.
        min_level: Minimum detection level (low, medium, high, critical).
        output_format: Output format ('csv' or 'jsonl').
        extra_args: Additional CLI arguments to pass to Hayabusa.

    Returns:
        HayabusaResult with parsed detection data.
    """
    result = HayabusaResult(evtx_path=evtx_path)

    # Validate input file
    evtx = Path(evtx_path)
    if not evtx.is_file():
        result.error = f"File not found: {evtx_path}"
        return result

    if evtx.suffix.lower() != ".evtx":
        result.error = f"Not an .evtx file: {evtx_path}"
        return result

    # Find Hayabusa binary
    binary = find_hayabusa_binary(hayabusa_path)
    if not binary:
        result.error = (
            "Hayabusa binary not found. Install from "
            "https://github.com/Yamato-Security/hayabusa/releases "
            "and ensure it is on your PATH or configure hayabusa_path."
        )
        return result

    # Prepare output path
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if output_format not in OUTPUT_FORMATS:
        output_format = "csv"

    ext = "csv" if output_format == "csv" else "jsonl"
    output_file = out_dir / f"{evtx.stem}_hayabusa.{ext}"
    result.output_path = str(output_file)
    result.output_format = output_format

    # Build command
    cmd = [
        binary,
        "csv-timeline" if output_format == "csv" else "json-timeline",
        "--no-wizard",
        "-f",
        str(evtx),
        "-o",
        str(output_file),
        "-m",
        min_level,
    ]
    if extra_args:
        cmd.extend(extra_args)

    logger.info(
        "hayabusa_start",
        evtx=str(evtx),
        output=str(output_file),
        min_level=min_level,
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result.returncode = proc.returncode

        if proc.returncode != 0:
            result.error = stderr.decode(errors="replace").strip()
            logger.error(
                "hayabusa_failed",
                returncode=proc.returncode,
                stderr=result.error[:500],
            )
            return result

    except FileNotFoundError:
        result.error = f"Hayabusa binary not executable: {binary}"
        return result
    except Exception as e:
        result.error = f"Failed to run Hayabusa: {e}"
        return result

    # Parse output
    if output_file.is_file():
        raw = output_file.read_text(errors="replace")
        if output_format == "csv":
            result.records = parse_csv_output(raw)
        else:
            result.records = parse_jsonl_output(raw)

        result.record_count = len(result.records)
        counts = _count_by_level(result.records)
        result.critical_count = counts["critical"]
        result.high_count = counts["high"]
        result.medium_count = counts["medium"]
        result.low_count = counts["low"]
        result.informational_count = counts["informational"]

    logger.info(
        "hayabusa_complete",
        evtx=str(evtx),
        detections=result.record_count,
        critical=result.critical_count,
        high=result.high_count,
    )

    return result
