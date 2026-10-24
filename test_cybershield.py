import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from ibmskillsbuild_CyberShield import Handler, analyze, parse_csv, phishing_check


def network(n, sources=1):
    return [dict(event_type='network', timestamp='2026-10-24T10:00:00Z',
                 source_ip=f'192.0.2.{i % sources + 1}', target='portal') for i in range(n)]


class DetectionTests(unittest.TestCase):
    def test_demo(self):
        result = analyze(parse_csv(Path('data/demo_events.csv').read_text()))
        self.assertEqual(result['summary'], dict(submitted=264, valid=264, rejected=0, alerts=7, accounts=3, two_factor_enabled=1))

    def test_flood_boundary(self):
        self.assertEqual(analyze(network(99))['alerts'], [])
        self.assertEqual(analyze(network(100))['alerts'][0]['type'], 'Suspected traffic flood')

    def test_distributed_threshold(self):
        self.assertEqual(analyze(network(100, 10))['alerts'][0]['type'], 'Suspected DDoS')

    def test_targets_are_separate(self):
        rows = network(100)
        for r in rows[:50]:
            r['target'] = 'other'
        self.assertEqual(analyze(rows)['alerts'], [])

    def test_utc_normalization(self):
        rows = network(100)
        for r in rows[:50]:
            r['timestamp'] = '2026-10-24T15:30:00+05:30'
        self.assertEqual(len(analyze(rows)['alerts']), 1)

    def test_minute_boundary_is_documented(self):
        rows = network(100)
        for r in rows[:50]:
            r['timestamp'] = '2026-10-24T10:01:00Z'
        self.assertEqual(analyze(rows)['alerts'], [])

    def test_login_failures_only(self):
        rows = [dict(event_type='login', timestamp='2026-10-24T10:00:00Z', source_ip='192.0.2.1', username='student', status='failure') for _ in range(5)]
        self.assertEqual(analyze(rows)['alerts'][0]['type'], 'Suspected brute force')
        rows[0]['status'] = 'success'
        self.assertEqual(analyze(rows)['alerts'], [])

    def test_latest_account_snapshot(self):
        rows = [dict(event_type='account', timestamp='2026-10-24T11:00:00Z', username='user', two_factor_enabled='true'),
                dict(event_type='account', timestamp='2026-10-24T10:00:00Z', username='user', two_factor_enabled='false')]
        self.assertEqual(analyze(rows)['alerts'], [])
        self.assertEqual(analyze(rows)['summary']['two_factor_enabled'], 1)

    def test_invalid_rows_are_reported(self):
        rows = network(2)
        rows[0]['source_ip'] = 'invalid'
        rows[1]['timestamp'] = '2026-10-24T10:00:00'
        self.assertEqual(analyze(rows)['summary']['rejected'], 2)

    def test_bad_csv_schema(self):
        for text in ['hello\nworld', 'event_type,event_type\nurl,url', 'event_type\nurl,extra']:
            with self.assertRaises(ValueError):
                parse_csv(text)

    def test_phishing_indicators(self):
        self.assertEqual(phishing_check('http://192.0.2.1/verify')['risk'], 'High')
        self.assertEqual(phishing_check('https://example.com')['score'], 0)
        with self.assertRaises(ValueError):
            phishing_check('javascript:alert(1)')

    def test_empty_input(self):
        self.assertEqual(analyze([])['summary']['valid'], 0)

    def test_bad_thresholds(self):
        with self.assertRaises(ValueError):
            analyze([], flood_threshold=0)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, payload=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        conn.request('GET' if payload is None else 'POST', path,
                     body=None if payload is None else json.dumps(payload),
                     headers=headers or {'Content-Type': 'application/json'})
        r = conn.getresponse()
        status, body = r.status, r.read()
        conn.close()
        return status, body

    def test_dashboard_and_demo(self):
        self.assertEqual(self.request('/')[0], 200)
        status, body = self.request('/api/analyze', {'demo': True})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['summary']['alerts'], 7)

    def test_invalid_requests(self):
        self.assertEqual(self.request('/api/url', {'url': 'not a URL'})[0], 400)
        self.assertEqual(self.request('/api/analyze', {'demo': True, 'login_threshold': 2.5})[0], 400)
        self.assertEqual(self.request('/missing')[0], 404)

    def test_cross_origin_rejected(self):
        self.assertEqual(self.request('/api/analyze', {'demo': True}, {'Content-Type': 'application/json', 'Origin': 'https://untrusted.example'})[0], 403)


if __name__ == '__main__':
    unittest.main()
