# Windows Event Log Analyzer

A defensive Windows 10/11 SOC portfolio project. It collects Windows Security events, normalizes login activity, detects suspicious patterns, and displays findings in a Streamlit dashboard.

## Features
- Collect Windows Security events: 4624, 4625, 4740, 4672, 4634, 4648, 4720, 4728, 4732, 4756, 1102.
- Parse login activity and identify repeated failed logons by account and source IP.
- Detect account lockouts, privileged logons, explicit credential use, account/group changes, and Security log clearing.
- Export normalized events and alerts as CSV/JSON.
- Streamlit dashboard with synthetic sample data.

## Setup (Windows PowerShell)
```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Preview using sample data
```powershell
python -m analyzer.analyze --input sample_logs\sample_events.json
streamlit run dashboard\app.py
```

## Collect real Windows Security events
Open PowerShell **as Administrator** in the project folder:
```powershell
python -m collector.collect_events --hours 24 --limit 5000
python -m analyzer.analyze --input data\events.json
```

## Detection rules
- 5 or more failed logons for the same account and source IP within 10 minutes: possible brute-force activity.
- Event ID 4740: account lockout.
- Event ID 4672: special privileges assigned (contextual signal, not automatically malicious).
- Event ID 4648: explicit credentials used.
- Event ID 1102: Security audit log cleared.
- Event IDs 4720, 4728, 4732, 4756: account/group changes.

Alerts are investigation leads, not proof of compromise. Correlate with surrounding events and validate account, source, timing, and endpoint context.

## Project structure
```text
collector/       Windows Event Log collection
analyzer/        parsing, detection, CLI analysis
dashboard/       Streamlit dashboard
config/          detection settings
sample_logs/     synthetic demonstration events
tests/           unit tests
data/            local event exports (gitignored)
reports/         generated reports (gitignored)
```

## Privacy and safe use
Use this tool only on systems you own or are authorized to administer. Windows Security logs may contain usernames, hostnames, and IP addresses. Do not publish raw logs or reports containing sensitive information.