# Linux Log Analysis with Python and Splunk

A hands-on cybersecurity lab exploring Linux authentication logs, simple Python-based triage, and Splunk searches and visualizations. The workflow is straightforward: review the evidence, identify patterns worth checking, and document what the data does—and does not—prove.

## Project goals

- Review Linux log entries for repeated authentication failures and unknown-user messages.
- Use Python to scan a defined range of log lines and export matches to CSV.
- Use Splunk Enterprise to search, group, and visualize authentication-related events.
- Record findings and follow-up steps in a report and workbook.

## Tools used

- Python 3
- Splunk Enterprise
- Microsoft Excel or a compatible spreadsheet application
- Visual Studio Code or another text editor

## Repository contents

```text
linux-log-analysis/
├── README.md
├── Linux_2k.log
├── log_analysis.py
├── suspicious_logs.csv
├── Linux_Log_Analysis_Findings.xlsx
├── Linux_Log_Analysis_Project_Report.docx
└── screenshots/
    └── Splunk_Authentication_Failure_Statistics.png
```

## How to run the Python script

Keep `log_analysis.py` and `Linux_2k.log` in the same folder, then run:

```bash
python log_analysis.py
```

On Windows, you can also try:

```powershell
py log_analysis.py
```

The script examines lines 200–500 and checks for `failed password`, `authentication failure`, `user unknown`, and `invalid user`. It prints matching entries and exports them to `suspicious_logs.csv`.

## Splunk searches

Basic count by host:

```spl
source="Linux_2k.log" "authentication failure"
| stats count by host
```

Group by extracted remote host and username:

```spl
source="Linux_2k.log" "authentication failure"
| rex "rhost=(?<source_host>\S+)"
| rex "user=(?<username>\S+)"
| stats count by source_host username
| sort - count
```

View activity over time:

```spl
source="Linux_2k.log" "authentication failure"
| timechart span=1h count
```

If your Splunk source name or field values differ, update the query to match the metadata shown in your environment.

## Findings from this lab run

- The supplied Python output contains **140 matching entries** from the selected range: **114 authentication-failure entries** and **26 unknown/invalid-user entries**.
- The Splunk authentication-failure search shown during the lab returned **490 events**.
- The grouped statistics view showed repeated counts associated with source hosts and usernames.
- The timechart showed activity at different times, including a visible spike that can help prioritize review.

These totals come from different scopes and search methods. Python checks only lines 200–500, while the Splunk search covers the indexed source and selected time range, so the numbers are not a direct one-to-one comparison.

## Analyst assessment

Repeated authentication failures—especially attempts involving privileged accounts or clusters of unknown-user messages—can be consistent with brute-force activity or account-enumeration attempts. They are indicators for further investigation, not proof of a successful compromise.

A sensible next step is to inspect nearby events, confirm timestamps and source fields, and search for successful authentication events around the same period. The sample also contains service-related messages that should be investigated separately.

## Limitations

- Python detection is keyword-based and can miss events worded differently.
- A keyword match may be benign and needs human review.
- The script assigns one category per line because it uses `if`/`elif` logic.
- The Python scan is limited to lines 200–500.
- Splunk counts depend on the selected time range, source, and query.
- This is a learning exercise using a sample dataset, not a production incident investigation.

## Dataset attribution

The sample log is associated with LogHub:

- [LogHub repository](https://github.com/logpai/loghub)

Splunk Enterprise downloads:

- [Splunk downloads](https://www.splunk.com/en_us/download.html)

Retain dataset attribution and check the dataset terms before redistributing source files. Do not publish real credentials, personal data, or sensitive internal logs.

## Possible improvements

- Parse timestamps, source IPs/hosts, and usernames into separate CSV columns.
- Add tests for the keyword detection logic.
- Compare Python and Splunk results using the same time window and definitions.
- Build a dashboard with a timeline, top source hosts, and top targeted usernames.
- Document which events were verified and which remain uncertain.
