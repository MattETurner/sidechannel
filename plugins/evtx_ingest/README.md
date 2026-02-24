# EVTX Ingest Plugin

Incident response analyst ingest workflow plugin for sidechannel. Analyzes Windows event log (`.evtx`) files using [Hayabusa](https://github.com/Yamato-Security/hayabusa) — a fast forensics timeline generator and threat hunting tool by Yamato Security.

## Features

- **Ingest Windows event logs** — Analyze `.evtx` files directly from Signal
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

```
/ingest /cases/evidence/Security.evtx
```

The plugin will:
1. Validate the `.evtx` file exists
2. Launch Hayabusa analysis in the background
3. Send a Signal notification when complete with a severity summary
4. Store full results in the plugin data directory

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
