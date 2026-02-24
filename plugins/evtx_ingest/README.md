# EVTX Ingest Plugin

Incident response analyst ingest workflow plugin for sidechannel. Analyzes Windows event log (`.evtx`) files using [Hayabusa](https://github.com/Yamato-Security/hayabusa) — a fast forensics timeline generator and threat hunting tool by Yamato Security.

## Features

- **Signal attachment ingest** — Send `.evtx` files directly via Signal and receive results automatically
- **Output file delivery** — Results are sent back as both a text summary and a downloadable file attachment
- **Hayabusa integration** — Automatic detection rule matching with severity classification
- **Background analysis** — Non-blocking analysis with status tracking and notifications
- **Severity breakdown** — Critical, high, medium, low, and informational detection counts
- **Configurable output** — CSV or JSONL output formats with adjustable detection levels

## Prerequisites

Install Hayabusa from the [releases page](https://github.com/Yamato-Security/hayabusa/releases):

```bash
# Download and extract Hayabusa
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64.zip
unzip hayabusa-linux-x64.zip
chmod +x hayabusa

# Option A: Add to PATH
sudo mv hayabusa /usr/local/bin/

# Option B: Configure path in settings.yaml (see below)
```

## Commands

| Command | Description |
|---------|-------------|
| `/ingest <path>` | Analyze a Windows `.evtx` file with Hayabusa |
| `/ingest-status` | Check status of the current analysis |
| `/ingest-results` | Show the latest analysis results summary |

## Usage

### Via Signal Attachment (Recommended)

Simply send a `.evtx` file as an attachment via Signal. The plugin will:
1. Detect the `.evtx` file automatically
2. Download it from Signal
3. Run Hayabusa analysis in the background
4. Send back a severity summary as a text message
5. Send the full results file as a Signal attachment

### Via Command

```
/ingest /cases/evidence/Security.evtx
```

## Configuration

Add to `config/settings.yaml`:

```yaml
plugins:
  evtx_ingest:
    enabled: true
    hayabusa_path: /usr/local/bin/hayabusa  # Optional if on PATH
    min_level: low              # Minimum detection level: low, medium, high, critical
    output_format: csv          # Output format: csv or jsonl
    max_summary_records: 20     # Max detections shown in summary
    extra_args: []              # Additional Hayabusa CLI arguments
```

## Output

Analysis results are stored in `data/plugins/evtx_ingest/results/` with filenames like `Security_hayabusa.csv`.

When ingesting via Signal attachment, the output file is also sent back as a Signal attachment for easy download.

Example summary output:

```
🔍 Hayabusa Analysis Complete
📄 Source: Security.evtx
📊 Total detections: 142

Severity breakdown:
  🔴 Critical: 3
  🟠 High: 12
  🟡 Medium: 45
  🔵 Low: 67
  ⚪ Informational: 15

Top detections (up to 20):
  [critical] Mimikatz Activity Detected @ 2024-01-15 08:23:41
  [critical] Pass-the-Hash Attack @ 2024-01-15 08:24:02
  ...

📁 Full results: data/plugins/evtx_ingest/results/Security_hayabusa.csv
```
