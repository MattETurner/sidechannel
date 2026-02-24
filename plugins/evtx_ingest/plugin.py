"""EVTX Ingest plugin — Windows event log analysis for incident response.

Provides analyst ingest workflows for Windows event log (.evtx) files
using Hayabusa for detection and timeline generation.

Analysts can send .evtx files directly via Signal as attachments, or
reference a file path on the server with the /ingest command.

Commands:
    /ingest <path>     — Run Hayabusa analysis on a Windows event log file.
    /ingest-status     — Check status of the current analysis.
    /ingest-results    — Show the latest analysis results summary.

Attachment workflow:
    Send a .evtx file via Signal → plugin auto-detects and analyzes it →
    results are sent back as both a text summary and the output file.
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional

from sidechannel.plugin_base import (
    AttachmentHandler,
    CommandHandler,
    HelpSection,
    SidechannelPlugin,
)

from .hayabusa import HayabusaResult, find_hayabusa_binary, run_hayabusa


class EvtxIngestPlugin(SidechannelPlugin):
    """Incident response plugin for ingesting and analyzing Windows event logs."""

    name = "evtx_ingest"
    description = "Windows event log ingest and Hayabusa analysis for incident response"
    version = "1.1.0"

    def __init__(self, ctx):
        super().__init__(ctx)
        self._current_task: Optional[asyncio.Task] = None
        self._latest_result: Optional[HayabusaResult] = None
        self._running_file: str = ""

    # ── commands ──────────────────────────────────────────────

    def commands(self) -> Dict[str, CommandHandler]:
        return {
            "ingest": self._handle_ingest,
            "ingest-status": self._handle_ingest_status,
            "ingest-results": self._handle_ingest_results,
        }

    # ── attachment handlers ──────────────────────────────────

    def attachment_handlers(self) -> List[AttachmentHandler]:
        return [
            AttachmentHandler(
                priority=10,
                match_fn=self._is_evtx_attachment,
                handle_fn=self._handle_evtx_attachment,
                description="EVTX file ingest via Hayabusa",
            )
        ]

    @staticmethod
    def _is_evtx_attachment(filename: str, content_type: str) -> bool:
        """Match .evtx file attachments."""
        if filename and filename.lower().endswith(".evtx"):
            return True
        if content_type in (
            "application/x-ms-evtx",
            "application/octet-stream",
        ) and filename.lower().endswith(".evtx"):
            return True
        return False

    async def _handle_evtx_attachment(
        self, sender: str, file_path: Path, filename: str, message: str
    ) -> str:
        """Handle an .evtx file sent as a Signal attachment."""
        # Check for Hayabusa binary
        hayabusa_path = self.ctx.get_config("hayabusa_path")
        binary = find_hayabusa_binary(hayabusa_path)
        if not binary:
            return (
                "❌ Hayabusa binary not found.\n\n"
                "Install Hayabusa from:\n"
                "https://github.com/Yamato-Security/hayabusa/releases\n\n"
                "Then either add it to your PATH or set hayabusa_path in config:\n"
                "  plugins:\n"
                "    evtx_ingest:\n"
                "      hayabusa_path: /path/to/hayabusa"
            )

        # Check if an analysis is already running
        if self._current_task and not self._current_task.done():
            return (
                f"⏳ Analysis already in progress on: {self._running_file}\n"
                "Use /ingest-status to check progress."
            )

        # Prepare output directory
        output_dir = str(self.ctx.data_dir / "results")

        # Launch analysis in background
        display_name = filename or file_path.name
        self._running_file = display_name
        self._current_task = asyncio.create_task(
            self._run_analysis(
                sender=sender,
                evtx_path=str(file_path),
                output_dir=output_dir,
                hayabusa_path=hayabusa_path,
                send_output_file=True,
            )
        )

        return (
            f"📎 Received: {display_name}\n"
            f"🚀 Starting Hayabusa analysis...\n"
            "You'll receive the results summary and output file when complete.\n"
            "Use /ingest-status to check progress."
        )

    # ── command handlers ─────────────────────────────────────

    async def _handle_ingest(self, sender: str, args: str) -> str:
        """Ingest and analyze a Windows .evtx file with Hayabusa."""
        evtx_path = args.strip()
        if not evtx_path:
            return (
                "Usage: /ingest <path-to-evtx-file>\n\n"
                "Example: /ingest /cases/evidence/Security.evtx\n\n"
                "💡 Tip: You can also send .evtx files directly as Signal "
                "attachments — they'll be analyzed automatically."
            )

        # Validate the file exists and has correct extension
        p = Path(evtx_path)
        if not p.is_file():
            return f"❌ File not found: {evtx_path}"
        if p.suffix.lower() != ".evtx":
            return f"❌ Not an .evtx file: {evtx_path}"

        # Check for Hayabusa binary
        hayabusa_path = self.ctx.get_config("hayabusa_path")
        binary = find_hayabusa_binary(hayabusa_path)
        if not binary:
            return (
                "❌ Hayabusa binary not found.\n\n"
                "Install Hayabusa from:\n"
                "https://github.com/Yamato-Security/hayabusa/releases\n\n"
                "Then either add it to your PATH or set hayabusa_path in config:\n"
                "  plugins:\n"
                "    evtx_ingest:\n"
                "      hayabusa_path: /path/to/hayabusa"
            )

        # Check if an analysis is already running
        if self._current_task and not self._current_task.done():
            return (
                f"⏳ Analysis already in progress on: {self._running_file}\n"
                "Use /ingest-status to check progress."
            )

        # Prepare output directory
        output_dir = str(self.ctx.data_dir / "results")

        # Launch analysis in background
        self._running_file = evtx_path
        self._current_task = asyncio.create_task(
            self._run_analysis(
                sender=sender,
                evtx_path=evtx_path,
                output_dir=output_dir,
                hayabusa_path=hayabusa_path,
                send_output_file=True,
            )
        )

        return (
            f"🚀 Starting Hayabusa analysis on: {p.name}\n"
            "You'll be notified when the analysis is complete.\n"
            "Use /ingest-status to check progress."
        )

    async def _handle_ingest_status(self, sender: str, args: str) -> str:
        """Check the status of the current analysis."""
        if self._current_task is None:
            return (
                "No analysis has been started.\n"
                "Use /ingest <path> or send an .evtx file to begin."
            )

        if not self._current_task.done():
            return f"⏳ Analysis in progress: {self._running_file}"

        if self._latest_result and self._latest_result.success:
            return (
                f"✅ Analysis complete: {Path(self._latest_result.evtx_path).name}\n"
                f"📊 {self._latest_result.record_count} detections found.\n"
                "Use /ingest-results to see the full summary."
            )

        if self._latest_result:
            return f"❌ Analysis failed: {self._latest_result.error}"

        return "Analysis task finished but no results are available."

    async def _handle_ingest_results(self, sender: str, args: str) -> str:
        """Show the latest analysis results summary."""
        if self._latest_result is None:
            return "No results available.\n" "Use /ingest <path> or send an .evtx file to analyze."

        max_records = self.ctx.get_config("max_summary_records", 20)
        return self._latest_result.summary(max_records=max_records)

    # ── background analysis ──────────────────────────────────

    async def _run_analysis(
        self,
        sender: str,
        evtx_path: str,
        output_dir: str,
        hayabusa_path: Optional[str],
        send_output_file: bool = False,
    ) -> None:
        """Run Hayabusa analysis and notify the sender when done."""
        try:
            min_level = self.ctx.get_config("min_level", "low")
            output_format = self.ctx.get_config("output_format", "csv")
            extra_args = self.ctx.get_config("extra_args")

            result = await run_hayabusa(
                evtx_path=evtx_path,
                output_dir=output_dir,
                hayabusa_path=hayabusa_path,
                min_level=min_level,
                output_format=output_format,
                extra_args=extra_args,
            )
            self._latest_result = result

            # Notify the analyst
            if result.success:
                summary = result.summary(max_records=self.ctx.get_config("max_summary_records", 20))
                await self.ctx.send_message(sender, summary)

                # Send the output file back via Signal
                if send_output_file and result.output_path:
                    output_file = Path(result.output_path)
                    if output_file.is_file():
                        await self.ctx.send_file(
                            sender,
                            output_file,
                            f"📎 Hayabusa results for {Path(evtx_path).name}",
                        )
            else:
                await self.ctx.send_message(
                    sender,
                    f"❌ Hayabusa analysis failed: {result.error}",
                )

        except Exception as e:
            self.ctx.logger.error("ingest_analysis_error", error=str(e))
            self._latest_result = HayabusaResult(
                evtx_path=evtx_path,
                error=str(e),
            )
            await self.ctx.send_message(
                sender,
                f"❌ Analysis error: {e}",
            )
        finally:
            self._running_file = ""

    # ── lifecycle ────────────────────────────────────────────

    async def on_stop(self) -> None:
        """Cancel any running analysis on shutdown."""
        if self._current_task and not self._current_task.done():
            self._current_task.cancel()
            try:
                await self._current_task
            except asyncio.CancelledError:
                pass

    # ── help ─────────────────────────────────────────────────

    def help_sections(self):
        return [
            HelpSection(
                title="Incident Response — EVTX Ingest",
                commands={
                    "ingest": "Analyze a Windows .evtx file with Hayabusa",
                    "ingest-status": "Check status of the current analysis",
                    "ingest-results": "Show the latest analysis results summary",
                },
            )
        ]
