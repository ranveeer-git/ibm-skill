"""CyberShield: offline, explainable security log analysis. Python 3.10+."""
import argparse
import csv
import io
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
FIELDS = ['event_type', 'timestamp', 'source_ip', 'target', 'username', 'status',
          'two_factor_enabled', 'url']
MAX_ROWS = 20000
MAX_BYTES = 5 * 1024 * 1024


def phishing_check(url):
    """Lexical indicators only; never opens URLs or makes network requests."""
    if len(url) > 4096:
        raise ValueError('URL exceeds 4096 characters.')
    try:
        p = urlsplit(url)
        host = p.hostname or ''
        if p.scheme not in ('http', 'https') or not host or re.search(r'\s', url):
            raise ValueError('URL must be a valid http:// or https:// address without spaces.')
        _ = p.port
    except ValueError as exc:
        raise ValueError('Invalid HTTP(S) URL.') from exc
    reasons = []
    if p.scheme == 'http':
        reasons.append(('Unencrypted HTTP', 15))
    if p.username is not None:
        reasons.append(('User information before @ can disguise the destination', 30))
    try:
        ipaddress.ip_address(host)
        reasons.append(('IP address used instead of a domain', 25))
    except ValueError:
        pass
    if 'xn--' in host or not host.isascii():
        reasons.append(('Internationalized domain requires visual review', 20))
    if len(url) > 120:
        reasons.append(('Unusually long URL', 10))
    if host.count('.') >= 4:
        reasons.append(('Many subdomains', 15))
    if re.search(r'(verify|password|signin|login|account|secure|update)', url, re.I):
        reasons.append(('Account or credential related wording', 10))
    score = min(100, sum(weight for _, weight in reasons))
    return {'url': url, 'score': score,
            'risk': 'High' if score >= 50 else 'Medium' if score >= 25 else 'Low',
            'reasons': [reason for reason, _ in reasons] or ['No configured lexical indicators'],
            'note': 'Heuristic score, not a probability. Low risk does not mean safe.'}


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
    if not reader.fieldnames or 'event_type' not in reader.fieldnames:
        raise ValueError('CSV must include an event_type header. Download the demo for the schema.')
    if len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError('Duplicate CSV headers are not allowed.')
    rows = []
    for number, row in enumerate(reader, 2):
        if number > MAX_ROWS + 1:
            raise ValueError(f'Maximum {MAX_ROWS} rows per upload.')
        if None in row:
            raise ValueError(f'Row {number}: more values than headers.')
        rows.append({str(k): (v or '').strip() for k, v in row.items()})
    return rows


def validate_rows(rows):
    valid, errors = [], []
    for number, original in enumerate(rows, 2):
        row = dict(original)
        try:
            kind = row.get('event_type', '').lower()
            row['event_type'] = kind
            required = {'network': ['timestamp', 'source_ip', 'target'],
                        'login': ['timestamp', 'source_ip', 'username', 'status'],
                        'account': ['timestamp', 'username', 'two_factor_enabled'],
                        'url': ['url']}
            if kind not in required:
                raise ValueError('event_type must be network, login, account, or url')
            for field in required[kind]:
                if not row.get(field):
                    raise ValueError(f'missing {field}')
            if kind != 'url':
                date = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
                if date.tzinfo is None:
                    raise ValueError('timestamp must include a timezone, e.g. +00:00 or Z')
                row['_time'] = date.astimezone(timezone.utc)
            if kind in ('network', 'login'):
                row['source_ip'] = str(ipaddress.ip_address(row['source_ip']))
            if kind == 'login':
                row['status'] = row['status'].lower()
                if row['status'] not in ('success', 'failure'):
                    raise ValueError('login status must be success or failure')
            if kind == 'account':
                row['two_factor_enabled'] = row['two_factor_enabled'].lower()
                if row['two_factor_enabled'] not in ('true', 'false', 'unknown'):
                    raise ValueError('two_factor_enabled must be true, false, or unknown')
            if kind == 'url':
                phishing_check(row['url'])
            valid.append(row)
        except (ValueError, TypeError) as exc:
            errors.append(f'Row {number}: {exc}')
    return valid, errors


def analyze(rows, flood_threshold=100, source_threshold=10, login_threshold=5):
    """Classify observations in fixed UTC one-minute buckets, never block traffic."""
    if not (1 <= flood_threshold <= 100000 and 2 <= source_threshold <= 10000
            and 2 <= login_threshold <= 10000):
        raise ValueError('Thresholds are out of range.')
    valid, errors = validate_rows(rows)
    network, failures, accounts, urls = defaultdict(list), defaultdict(list), {}, []
    timeline = defaultdict(int)
    for row in valid:
        kind = row['event_type']
        minute = row['_time'].replace(second=0, microsecond=0).isoformat() if '_time' in row else ''
        if minute:
            timeline[minute] += 1
        if kind == 'network':
            network[(minute, row['target'])].append(row)
        elif kind == 'login' and row['status'] == 'failure':
            failures[(minute, row['source_ip'], row['username'])].append(row)
        elif kind == 'account':
            previous = accounts.get(row['username'])
            if previous is None or row['_time'] >= previous['_time']:
                accounts[row['username']] = row
        elif kind == 'url':
            urls.append(phishing_check(row['url']))
    alerts = []
    def alert(kind, severity, subject, window, evidence, action):
        alerts.append(dict(type=kind, severity=severity, subject=subject,
                           window=window, evidence=evidence, action=action))
    for (minute, target), group in sorted(network.items()):
        sources = len({r['source_ip'] for r in group})
        if len(group) >= flood_threshold:
            distributed = sources >= source_threshold
            alert('Suspected DDoS' if distributed else 'Suspected traffic flood', 'High', target,
                  minute, f'{len(group)} requests from {sources} sources in one UTC minute',
                  'Compare with baseline and service health; review rate limiting and upstream protection.')
    for (minute, source, user), group in sorted(failures.items()):
        if len(group) >= login_threshold:
            alert('Suspected brute force', 'High', f'{user} from {source}', minute,
                  f'{len(group)} failed logins in one UTC minute',
                  'Review authentication logs; consider throttling and verify MFA enrollment.')
    for user, row in sorted(accounts.items()):
        state = row['two_factor_enabled']
        if state != 'true':
            alert('2FA disabled' if state == 'false' else '2FA status unknown',
                  'Medium' if state == 'false' else 'Low', user, row['_time'].isoformat(),
                  f'Latest account inventory reports two_factor_enabled={state}',
                  'Verify the current identity-provider policy and enroll a second factor if needed.')
    for result in urls:
        if result['risk'] != 'Low':
            alert('Suspicious URL', result['risk'], result['url'], '',
                  '; '.join(result['reasons']), 'Verify the domain independently before entering credentials.')
    return {'summary': {'submitted': len(rows), 'valid': len(valid), 'rejected': len(errors),
                        'alerts': len(alerts), 'accounts': len(accounts),
                        'two_factor_enabled': sum(r['two_factor_enabled'] == 'true' for r in accounts.values())},
            'alerts': alerts, 'errors': errors, 'urls': urls,
            'timeline': [{'minute': k, 'events': v} for k, v in sorted(timeline.items())],
            'thresholds': {'requests_per_minute': flood_threshold, 'distinct_sources': source_threshold,
                           'failures_per_source_user_minute': login_threshold}}


HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CyberShield Security Dashboard</title>
<style>
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif;background:#0b1120;color:#e2e8f0}
body{margin:0}header{padding:28px 5%;background:#111d32;border-bottom:1px solid #304361}h1{margin:8px 0;font-size:32px}p{color:#aebfd4;line-height:1.6}.tag{color:#5eead4;font-size:12px;letter-spacing:2px}main{max-width:1280px;margin:auto;padding:28px}section,.card{background:#131f33;border:1px solid #304361;border-radius:14px;padding:22px;margin-bottom:22px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.card strong{display:block;font-size:32px;margin-top:8px;color:#5eead4}.card{font-size:14px}h2{margin:0 0 16px;font-size:20px}button,.download{background:#5eead4;color:#082a30;border:0;border-radius:7px;padding:11px 17px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}button.secondary{background:#2a3d59;color:white}input,select{background:#0b1425;color:white;border:1px solid #58708e;border-radius:6px;padding:10px;max-width:100%;box-sizing:border-box}label{display:inline-flex;flex-direction:column;gap:7px;margin:5px 14px 12px 0;font-size:13px}input[type=number]{width:145px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center}table{border-collapse:collapse;width:100%;min-width:950px;font-size:13px}td,th{padding:14px 10px;border-bottom:1px solid #304361;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{color:#aebfd4}td:first-child{min-width:125px}.scroll{overflow:auto}.badge{white-space:nowrap;display:inline-block;border-radius:20px;padding:4px 9px;background:#40351c;color:#fcd34d}.High{background:#4a2335;color:#fda4af}.Low{background:#163d40;color:#5eead4}.empty{padding:20px;color:#aebfd4}.bar{height:14px;background:#5eead4;border-radius:4px;min-width:2px}.time-row{display:grid;grid-template-columns:195px 1fr 60px;gap:14px;align-items:center;font-size:12px;margin:12px 0}#message{padding:12px 0;color:#fcd34d}small{color:#aebfd4}#url{width:min(600px,100%)}footer{color:#aebfd4;font-size:12px;padding:5px 0 30px}@media(max-width:750px){.grid{grid-template-columns:1fr 1fr}main{padding:15px}.time-row{grid-template-columns:150px 1fr 40px}}
</style></head><body><header><div class="tag">CYBERSECURITY BOOTCAMP • PYTHON PROJECT</div><h1>CyberShield</h1><p>Understand suspicious traffic, login activity, phishing indicators and 2FA coverage.</p><small>Local analysis • Explainable rules • No active scanning</small></header><main>
<section><h2>Analyze security events</h2><p>Load the synthetic demonstration or upload a CSV using the same columns. Each network row represents one request. Maximum 20,000 rows / 5 MB.</p>
<label>Requests per minute<input id="flood" type="number" min="1" max="100000" value="100"></label><label>Sources for DDoS flag<input id="sources" type="number" min="2" max="10000" value="10"></label><label>Failed logins per minute<input id="logins" type="number" min="2" max="10000" value="5"></label>
<div class="toolbar"><button id="demo">Load demo</button><label>Upload event CSV<input id="file" type="file" accept=".csv,text/csv"></label><button id="upload" class="secondary">Analyze CSV</button><a class="download" href="/demo.csv" download>Download demo CSV</a><button id="export" class="secondary" disabled>Export findings JSON</button></div><div id="message" role="status" aria-live="polite">Load the demo to begin.</div></section>
<div class="grid"><div class="card">Valid events<strong id="valid">—</strong></div><div class="card">Findings<strong id="alerts">—</strong></div><div class="card">2FA enabled / accounts<strong id="mfa">—</strong></div><div class="card">Rejected rows<strong id="rejected">—</strong></div></div>
<section><div class="toolbar"><h2>Findings and response guidance</h2><label>Severity<select id="filter"><option>All</option><option>High</option><option>Medium</option><option>Low</option></select></label></div><div class="scroll"><table><thead><tr><th>Finding</th><th>Severity</th><th>Subject and UTC time</th><th>Evidence</th><th>Suggested response</th></tr></thead><tbody id="findings"></tbody></table></div><div id="empty" class="empty">No analysis loaded.</div></section>
<section><h2>Event volume by UTC minute</h2><p>Counts all timestamped valid rows; URL-only observations are excluded. Fixed minute buckets can miss bursts spanning a minute boundary.</p><div id="chart"></div></section>
<section><h2>Inspect a URL without visiting it</h2><p>Checks visible URL characteristics only. A low score is not a safety verdict.</p><label style="display:block">HTTP or HTTPS URL<input id="url" type="text" placeholder="https://example.com"></label><button id="check">Check URL</button><p id="urlresult" role="status"></p></section>
<section><h2>Data quality and scope</h2><div id="errors">Rejected rows will appear here.</div><p>2FA is reported from the latest supplied account inventory, not verified against a live account. This educational prototype does not monitor your computer, block attacks, or attribute advanced persistent threats (APTs). Findings require investigation.</p></section><footer>CyberShield / Python standard library / All analysis stays in this local process. No URL is fetched.</footer></main>
<script>
const $=id=>document.getElementById(id);let report=null;
async function api(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.error||'Request failed');return j}
function cell(tr,text){const td=document.createElement('td');td.textContent=text;tr.append(td);return td}
function findings(){const list=report?report.alerts.filter(a=>$('filter').value==='All'||a.severity===$('filter').value):[];$('findings').replaceChildren();for(const a of list){const tr=document.createElement('tr');cell(tr,a.type);const badge=document.createElement('span');badge.className='badge '+a.severity;badge.textContent=a.severity;cell(tr,'').append(badge);cell(tr,a.subject+' '+a.window);cell(tr,a.evidence);cell(tr,a.action);$('findings').append(tr)}$('empty').textContent=list.length?'':report?'No findings match this view. This does not establish that the input is safe.':'No analysis loaded.'}
function render(j){report=j;$('valid').textContent=j.summary.valid;$('alerts').textContent=j.summary.alerts;$('mfa').textContent=j.summary.accounts?j.summary.two_factor_enabled+' / '+j.summary.accounts:'No data';$('rejected').textContent=j.summary.rejected;$('export').disabled=false;findings();$('errors').replaceChildren();for(const e of j.errors){const p=document.createElement('p');p.textContent=e;$('errors').append(p)}if(!j.errors.length)$('errors').textContent='No invalid rows found.';$('chart').replaceChildren();const max=Math.max(1,...j.timeline.map(t=>t.events));for(const t of j.timeline){const row=document.createElement('div');row.className='time-row';const label=document.createElement('span');label.textContent=t.minute.replace('T',' ').replace('+00:00','');const bar=document.createElement('div');bar.className='bar';bar.style.width=(100*t.events/max)+'%';const n=document.createElement('span');n.textContent=t.events;row.append(label,bar,n);$('chart').append(row)}$('message').textContent='Analysis complete. '+j.summary.valid+' valid rows; '+j.summary.rejected+' rejected.'}
async function run(demo){try{$('message').textContent='Analyzing…';const file=$('file').files[0];if(!demo&&!file)throw Error('Choose a CSV file first.');if(file&& !demo &&file.size>5242880)throw Error('File exceeds 5 MB.');const data={demo,flood_threshold:Number($('flood').value),source_threshold:Number($('sources').value),login_threshold:Number($('logins').value)};if(!demo)data.csv=await file.text();render(await api('/api/analyze',data))}catch(e){$('message').textContent=e.message}}
$('demo').onclick=()=>run(true);$('upload').onclick=()=>run(false);$('filter').onchange=findings;$('check').onclick=async()=>{try{const j=await api('/api/url',{url:$('url').value});$('urlresult').textContent=j.risk+' concern • '+j.score+'/100 — '+j.reasons.join('; ')+'. '+j.note}catch(e){$('urlresult').textContent=e.message}};$('export').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='cybershield-findings.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload, kind='application/json; charset=utf-8'):
        body = json.dumps(payload).encode() if kind.startswith('application/json') else payload.encode()
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        host = self.headers.get('Host', '')
        expected = f'127.0.0.1:{self.server.server_port}'
        localhost = f'localhost:{self.server.server_port}'
        origin = self.headers.get('Origin')
        return host in (expected, localhost) and (origin is None or origin in ('http://' + expected, 'http://' + localhost))

    def do_GET(self):
        if not self.allowed():
            return self.reply(403, {'error': 'Local requests only.'})
        if self.path == '/':
            self.reply(200, HTML, 'text/html; charset=utf-8')
        elif self.path == '/demo.csv':
            self.reply(200, (ROOT / 'data/demo_events.csv').read_text(encoding='utf-8'), 'text/csv; charset=utf-8')
        else:
            self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.allowed():
            return self.reply(403, {'error': 'Local requests only.'})
        if self.path not in ('/api/analyze', '/api/url'):
            return self.reply(404, {'error': 'Not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_BYTES + 500000:
                return self.reply(413, {'error': 'Request too large or empty.'})
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                return self.reply(415, {'error': 'Expected application/json.'})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object.')
            if self.path == '/api/url':
                if not isinstance(data.get('url'), str):
                    raise ValueError('URL must be text.')
                return self.reply(200, phishing_check(data['url']))
            text = (ROOT / 'data/demo_events.csv').read_text(encoding='utf-8') if data.get('demo') is True else data.get('csv', '')
            if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
                raise ValueError('CSV must be text under 5 MB.')
            thresholds = {}
            for key, default in [('flood_threshold', 100), ('source_threshold', 10), ('login_threshold', 5)]:
                value = data.get(key, default)
                if type(value) is not int:
                    raise ValueError('Thresholds must be whole numbers.')
                thresholds[key] = value
            self.reply(200, analyze(parse_csv(text), **thresholds))
        except (ValueError, TypeError, csv.Error) as exc:
            self.reply(400, {'error': str(exc)})

    def log_message(self, format, *args):
        pass  # Do not write uploaded account or URL data to access logs.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--analyze', type=Path, help='Analyze a CSV instead of starting the dashboard')
    parser.add_argument('--output', type=Path, help='Save command-line findings as JSON')
    args = parser.parse_args()
    if args.analyze:
        try:
            if args.analyze.stat().st_size > MAX_BYTES:
                parser.error('CSV exceeds 5 MB.')
            result = analyze(parse_csv(args.analyze.read_text(encoding='utf-8-sig')))
            text = json.dumps(result, indent=2)
            if args.output:
                args.output.write_text(text, encoding='utf-8')
            else:
                print(text)
        except (OSError, ValueError, csv.Error) as exc:
            parser.error(str(exc))
    else:
        if not 1 <= args.port <= 65535:
            parser.error('Port must be between 1 and 65535.')
        with ThreadingHTTPServer(('127.0.0.1', args.port), Handler) as server:
            print(f'CyberShield is running at http://127.0.0.1:{args.port} — Ctrl+C to stop.')
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print('\nStopped.')


if __name__ == '__main__':
    main()
