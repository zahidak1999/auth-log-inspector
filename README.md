# Auth Log Analyzer

A small Python command-line tool that summarizes SSH authentication events from syslog text, JSON, JSON Lines, or a custom HTTPS endpoint. It reports repeated failed logins by source address and flags a successful login when it follows a configurable number of failures from the same address.

It can read a local file or fetch one from a custom HTTPS endpoint. It does not upload the log to another service or modify the source file.

## Requirements

- Python 3.10 or newer
- No runtime dependencies beyond Python's standard library

## Install

From the project folder, create a virtual environment and install the package:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

The same commands work on macOS and Linux if you replace `py` with `python3` and `.\.venv\Scripts\python.exe` with `.venv/bin/python`.

## Analyze a local file

```powershell
.\.venv\Scripts\python.exe -m authlog_analyzer samples\auth.log
```

The input format is detected automatically. To force a format, use `--format text`, `--format json`, or `--format jsonl`.

Try the included structured JSON example:

```powershell
.\.venv\Scripts\python.exe -m authlog_analyzer samples\auth-events.json
```

You can pass any readable local file in the supported syslog format:

```powershell
.\.venv\Scripts\python.exe -m authlog_analyzer "C:\logs\auth.log" --threshold 5 --json report.json
```

## Fetch from a custom server

The endpoint must accept an HTTPS `GET` and return either a supported plain-text log or JSON response. Supported JSON includes a single event object, an array of events, JSON Lines, and common `events`, `logs`, `records`, `items`, `results`, `data`, or Elasticsearch `hits.hits` wrappers. The analyzer recognizes common fields such as `source.ip`, `user.name`, `event.outcome`, and `message`. Other JSON records are ignored unless you map their fields.

```powershell
.\.venv\Scripts\python.exe -m authlog_analyzer --url "https://logs.example.com/exports/auth.log"
```

For JSON or JSON Lines, auto-detection usually works. You can set `--format json` or `--format jsonl` explicitly. If your server uses different field names, map them on the command line. For example, for events shaped like `{"clientAddress":"203.0.113.24","principal":"admin","loginState":"failed"}`:

```powershell
.\.venv\Scripts\python.exe -m authlog_analyzer --url "https://logs.example.com/api/events" --format json --json-ip-field clientAddress --json-user-field principal --json-status-field loginState
```

Field paths may be dotted, for example `client.address` or `event.outcome`. Status values should contain recognizable terms such as `failed`, `failure`, `denied`, `success`, or `accepted`.

For an endpoint that requires a bearer token, put the token in an environment variable instead of writing it in the command or URL:

```powershell
$env:AUTH_LOG_TOKEN = "your-token"
.\.venv\Scripts\python.exe -m authlog_analyzer --url "https://logs.example.com/api/auth-log" --token-env AUTH_LOG_TOKEN --timeout 20 --max-bytes 20000000
Remove-Item Env:AUTH_LOG_TOKEN
```

The 10 MiB default is a guard against a server returning an unexpectedly large response and using excessive memory. Increase it with `--max-bytes` if needed; it applies only to remote downloads, not local files. The analyzer currently reads the full response into memory, so larger values use more memory.

The tool verifies HTTPS certificates, refuses redirects to another server or to plain HTTP, and omits URL query strings from its printed report. The response is processed in memory and is not saved unless you explicitly use `--json`. A URL with a query string is sent as supplied, so do not put credentials in the URL; use `--token-env` for bearer authentication.

On macOS or Linux, set the token with `export AUTH_LOG_TOKEN="your-token"` and replace the executable path with `.venv/bin/python`.

## Run the tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## What it checks

- Counts recognized failed and successful SSH login events.
- Groups failures by source IP and username.
- Reports source addresses that meet the failure threshold.
- Flags a success following at least the threshold number of failures from the same source since its previous successful login.
- Ignores unrelated or malformed lines and reports how many it skipped.

This is a learning and triage aid, not an intrusion detector. A finding is a reason to review the surrounding log context, not proof of malicious activity. The parser supports common traditional syslog `auth.log` SSH messages; other formats may be ignored.

## Privacy

Authentication logs can contain usernames, addresses, and operational details. Keep real logs and reports private. The included sample uses invented usernames and documentation-only IP ranges. Do not commit real logs, report files, tokens, or server credentials to GitHub.

## Project layout

```text
src/authlog_analyzer/   Parser, analysis logic, remote fetcher, and CLI
tests/                  Automated tests
samples/                Sanitized sample log
```

## License

MIT. See [LICENSE](LICENSE).
