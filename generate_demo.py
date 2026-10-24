"""Generate deterministic synthetic observations; no external dataset required."""
import csv
from pathlib import Path
from YourName_CyberShield import FIELDS


def generate():
    rows = []
    def add(kind, **values):
        rows.append(dict(event_type=kind, **values))
    for i in range(20):
        add('network', timestamp=f'2026-10-24T10:00:{i:02d}Z', source_ip='192.0.2.10', target='student-portal')
    for i in range(120):
        add('network', timestamp=f'2026-10-24T10:01:{i % 60:02d}Z', source_ip=f'198.51.100.{i % 12 + 1}', target='student-portal')
    for i in range(110):
        add('network', timestamp=f'2026-10-24T10:02:{i % 60:02d}Z', source_ip='203.0.113.25', target='api-service')
    for i in range(7):
        add('login', timestamp=f'2026-10-24T10:03:{i:02d}Z', source_ip='203.0.113.40', username='demo-admin', status='failure')
    add('login', timestamp='2026-10-24T10:03:20Z', source_ip='192.0.2.10', username='demo-student', status='success')
    for user, status in [('demo-admin', 'false'), ('demo-student', 'true'), ('demo-guest', 'unknown')]:
        add('account', timestamp='2026-10-24T10:04:00Z', username=user, two_factor_enabled=status)
    for url in ['https://example.com', 'http://192.0.2.99/login/verify', 'https://example.com@account.verify.secure.example.test/login']:
        add('url', url=url)
    folder = Path(__file__).resolve().parent / 'data'
    folder.mkdir(exist_ok=True)
    with (folder / 'demo_events.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f'Generated {len(rows)} synthetic rows.')


if __name__ == '__main__':
    generate()
