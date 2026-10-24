# CyberShield Security Dashboard

A Python cybersecurity bootcamp project for analyzing suspected DDoS traffic,
traffic floods, brute-force login attempts, phishing URL indicators, and account
two-factor authentication (2FA) coverage. Includes a local browser dashboard,
CSV import, adjustable detection thresholds, an event-volume chart, and JSON export.

## Run

Install Python 3.10 or newer, open a terminal in this project folder, and run:

```powershell
python YourName_CyberShield.py
```

Open **http://127.0.0.1:8000** in your browser and click **Load demo**.
Stop with Ctrl+C. If the port is occupied, use `--port 8001` and open that port.
The application and tests use only Python's standard library; no pip installation
is required. `requirements.txt` records this. Internet access is not required.

## Submission files

- `YourName_CyberShield.py`: complete application code, including dashboard UI.
- `requirements.txt`: runtime dependency declaration.
- `YourName_ProjectReport.docx`: project documentation.
- `README.md`: overview, setup, data provenance, schema, limitations, and demo steps.
- `data/demo_events.csv`: included synthetic dataset.
- `generate_demo.py`: deterministic dataset generator.
- `test_cybershield.py`: automated detection and HTTP tests.

Replace `YourName` with your name in the application and report filenames before
submission. If renaming the Python module, update imports in the generator and
tests as well. The attachment allows `.py` or `.ipynb`; this project supplies `.py`.
Fill in the student name in the report. Keep the `data` folder beside the application.

## Dataset and provenance

Dataset link: [included demo events](data/demo_events.csv).
Generator: [generate_demo.py](generate_demo.py).
The 264 observations are generated locally, not collected from people or an external
service. IPs are documentation addresses and URLs are illustrative. There is no
external dataset download and no claim of training or evaluating a machine-learning model.

Regenerate and test:

```powershell
python generate_demo.py
python -m unittest -v
python YourName_CyberShield.py --analyze data/demo_events.csv --output findings.json
```

## Input schema

Use a UTF-8 CSV with the following headers; irrelevant values can be blank:

```text
event_type,timestamp,source_ip,target,username,status,two_factor_enabled,url
```

| Event type | Required fields | Meaning |
| --- | --- | --- |
| network | timestamp, source_ip, target | One request to a target service per row |
| login | timestamp, source_ip, username, status | status is success or failure |
| account | timestamp, username, two_factor_enabled | 2FA state is true, false, or unknown |
| url | url | Absolute HTTP or HTTPS URL; no request is made |

`event_type` is required on every row. Timestamps use ISO 8601 with a timezone,
such as `2026-10-24T10:00:00Z` or `2026-10-24T15:30:00+05:30`.
Account rows are inventory snapshots. The newest timestamp for each username wins;
for equal timestamps the last input row wins. No account rows means no 2FA coverage data.
Missing 2FA values are rejected, not interpreted as disabled.
Malformed rows are skipped with row-specific errors. Invalid headers reject the upload.
Upload limit: 5 MB and 20,000 rows. Exported results include subjects and evidence;
handle exports with the same care as source logs. Uploaded data stays in memory.

## Detection rules

| Finding | Default rule |
| --- | --- |
| Suspected DDoS | At least 100 requests to one target from at least 10 distinct source IPs in one fixed UTC minute |
| Suspected traffic flood | At least 100 requests to one target with fewer than 10 source IPs in one UTC minute |
| Suspected brute force | At least 5 failed logins for one source IP and username pair in one UTC minute |
| 2FA disabled or unknown | Latest inventory snapshot reports false or unknown |
| Suspicious URL | Sum of lexical indicator weights reaches 25; High begins at 50 |

URL weights: HTTP 15, embedded user information 30, IP hostname 25,
internationalized domain 20, URL longer than 120 characters 10, at least four
hostname dots 15, and account/credential wording 10. Scores cap at 100 and are
not calibrated probabilities. Internationalized domains and login wording can be legitimate.

## Demonstration sequence

1. Start the application and load the demo.
2. Show 264 valid events, seven findings, and one of three accounts reporting 2FA enabled.
3. Explain one DDoS flag, one single-source flood, one brute-force flag, two 2FA findings,
   and two suspicious URL findings. These are six categories and seven findings.
4. Filter findings by severity and inspect the evidence and suggested response.
5. Change the request threshold to 150 and reload the demo; the two traffic findings disappear.
6. Check `https://example.com`, then `http://192.0.2.99/login/verify` in the URL checker.
7. Export the results as JSON. Download and re-upload the demo CSV to demonstrate import.

## Architecture and technologies

Python `http.server` serves a loopback-only HTTP dashboard and JSON API. `csv`
parses input, `datetime` normalizes timezones, `ipaddress` validates sources, and
`urllib.parse` inspects URLs without fetching them. Embedded HTML, CSS, and plain
JavaScript provide the UI without a build step, CDN, or third-party runtime dependencies.
All uploaded text is inserted using `textContent` rather than interpreted as HTML.
Host and Origin checks restrict browser requests to the local service. The app is
an educational local tool, not a production multi-user server.

Flow: CSV → validation → UTC normalization → event grouping and URL scoring →
findings with evidence → dashboard / JSON export.

## Limitations and future work

Rules flag suspicions, not verified attacks. Legitimate popularity spikes may look
like DDoS. Fixed minute buckets miss some bursts across boundaries; slow or distributed
credential attacks may evade the per-source, per-user login rule. Network rows must
represent single requests, not pre-aggregated traffic counts. Duplicate input rows
are counted, so deduplicate upstream where appropriate.

URL analysis does not inspect page content, redirects, domain reputation, or ownership.
A low score does not establish safety. 2FA checking audits supplied enrollment data;
it does not test authentication, generate OTPs, or connect to an identity provider.
This project does not capture live packets, block traffic, detect every attack type,
or identify/attribute advanced persistent threats (APTs). No accuracy percentage is
claimed from synthetic examples. Future improvements include authorized log ingestion,
sliding windows, baseline tuning, labeled evaluation, and identity-provider integration.

# ibm-skill
