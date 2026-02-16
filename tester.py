#!/usr/bin/env python3
"""
Magento Open Source Security Assessment Tool
=============================================
A penetration testing tool for Magento CMS Community Edition.
Designed for authorized security research and responsible vulnerability disclosure.

Author: Tester Present - Specialist Automotive Solutions
WARNING: Only use against systems you own or have explicit written authorization to test. Lol.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font as tkfont
import threading
import requests
import json
import re
import time
import socket
import ssl
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MagentoScanner:
    MAGENTO_FINGERPRINTS = {
        '/magento_version': 'Version endpoint',
        '/admin': 'Default admin panel',
        '/admin_custom': 'Custom admin panel',
        '/downloader': 'Magento Connect Manager',
        '/index.php/admin': 'Admin via index.php',
        '/app/etc/local.xml': 'Database config (M1)',
        '/app/etc/env.php': 'Environment config (M2)',
        '/app/etc/config.php': 'Module config (M2)',
        '/var/log/system.log': 'System log exposure',
        '/var/log/debug.log': 'Debug log exposure',
        '/var/log/exception.log': 'Exception log exposure',
        '/var/report/': 'Error reports directory',
        '/errors/': 'Error handler directory',
        '/api/rest/': 'REST API (M1)',
        '/rest/V1/store/storeConfigs': 'REST API Store Config (M2)',
        '/rest/V1/directory/countries': 'REST API Countries (M2)',
        '/rest/V1/products': 'REST API Products (M2)',
        '/rest/V1/customers/search': 'REST API Customer Search (M2)',
        '/rest/V1/cmsPage/search': 'REST API CMS Search (M2)',
        '/rest/V1/modules': 'REST API Modules List (M2)',
        '/graphql': 'GraphQL endpoint (M2)',
        '/soap/default?wsdl': 'SOAP API WSDL (M2)',
        '/soap/default?wsdl_list': 'SOAP API Service List (M2)',
        '/setup/': 'Setup wizard (M2)',
        '/update/': 'Update wizard (M2)',
        '/dev/tests/': 'Test directory exposure',
        '/phpinfo.php': 'PHP info page',
        '/info.php': 'PHP info page (alt)',
        '/server-status': 'Apache server status',
        '/server-info': 'Apache server info',
        '/.git/HEAD': 'Git repository exposure',
        '/.env': 'Environment file exposure',
        '/.htaccess': 'Apache config exposure',
        '/composer.json': 'Composer dependencies (M2)',
        '/composer.lock': 'Composer lockfile (M2)',
        '/package.json': 'Node dependencies',
        '/grunt-config.json': 'Grunt config (M2)',
        '/nginx.conf.sample': 'Nginx sample config (M2)',
        '/RELEASE_NOTES.txt': 'Release notes',
        '/CHANGELOG.md': 'Changelog',
        '/LICENSE.txt': 'License file',
        '/LICENSE_AFL.txt': 'AFL License',
        '/pub/static/deployed_version.txt': 'Deployed version (M2)',
        '/pub/errors/': 'Public error handler (M2)',
        '/sitemap.xml': 'Sitemap',
        '/robots.txt': 'Robots.txt',
        '/crossdomain.xml': 'Flash crossdomain policy',
        '/skin/frontend/': 'Frontend skin dir (M1)',
        '/skin/adminhtml/': 'Admin skin dir (M1)',
        '/js/mage/': 'Mage JS library (M1)',
        '/pub/media/catalog/': 'Catalog media (M2)',
        '/media/catalog/': 'Catalog media (M1)',
        '/static/_requirejs/': 'RequireJS bundles (M2)',
        '/cron.php': 'Cron endpoint',
        '/get.php': 'Get.php handler (M1)',
    }

    SECURITY_HEADERS = [
        'Strict-Transport-Security', 'Content-Security-Policy',
        'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection',
        'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy',
        'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy',
    ]

    KNOWN_CVES = [
        {'id': 'CVE-2024-34102', 'severity': 'CRITICAL', 'cvss': 9.8, 'name': 'CosmicSting - XXE/RCE',
         'affected': 'Magento 2.x < 2.4.7-p1', 'description': 'XML External Entity injection allowing unauthenticated RCE via crafted XML in API endpoints.', 'check_type': 'version'},
        {'id': 'CVE-2024-20720', 'severity': 'CRITICAL', 'cvss': 9.1, 'name': 'OS Command Injection via Layout Template',
         'affected': 'Magento 2.x < 2.4.6-p4', 'description': 'Arbitrary code execution through crafted layout update XML in CMS blocks.', 'check_type': 'version'},
        {'id': 'CVE-2023-38218', 'severity': 'HIGH', 'cvss': 8.1, 'name': 'IDOR - Account Takeover',
         'affected': 'Magento 2.x < 2.4.7', 'description': 'Insecure Direct Object Reference allowing authenticated customer account takeover.', 'check_type': 'version'},
        {'id': 'CVE-2022-24086', 'severity': 'CRITICAL', 'cvss': 9.8, 'name': 'Template Injection RCE (Checkout)',
         'affected': 'Magento 2.x < 2.4.3-p2, 2.3.7-p3', 'description': 'Improper input validation during checkout allowing unauthenticated RCE.', 'check_type': 'version'},
        {'id': 'CVE-2022-24087', 'severity': 'CRITICAL', 'cvss': 9.8, 'name': 'Template Injection RCE (Email Templates)',
         'affected': 'Magento 2.x < 2.4.3-p2', 'description': 'Improper input validation in email templates allowing authenticated RCE.', 'check_type': 'version'},
        {'id': 'CVE-2021-21024', 'severity': 'CRITICAL', 'cvss': 9.1, 'name': 'Blind SQL Injection',
         'affected': 'Magento 2.x < 2.4.2', 'description': 'SQL injection vulnerability in catalog-related functionality.', 'check_type': 'version'},
        {'id': 'CVE-2021-36044', 'severity': 'HIGH', 'cvss': 7.5, 'name': 'GraphQL Rate Limiting Bypass',
         'affected': 'Magento 2.x < 2.4.3', 'description': 'Insufficient rate limiting on GraphQL mutations allowing brute force attacks.', 'check_type': 'endpoint', 'endpoint': '/graphql'},
        {'id': 'CVE-2020-9689', 'severity': 'HIGH', 'cvss': 8.8, 'name': 'Path Traversal Arbitrary Write',
         'affected': 'Magento 2.x < 2.3.5-p2, 2.4.0', 'description': 'Directory traversal allowing arbitrary file write by authenticated admin.', 'check_type': 'version'},
        {'id': 'CVE-2019-8118', 'severity': 'HIGH', 'cvss': 7.5, 'name': 'Information Disclosure',
         'affected': 'Magento 2.x < 2.3.3, 2.2.10', 'description': 'Unauthenticated information disclosure via API endpoints.', 'check_type': 'version'},
        {'id': 'CVE-2019-7139', 'severity': 'CRITICAL', 'cvss': 9.8, 'name': 'SQL Injection (Elasticsearch)',
         'affected': 'Magento 2.x < 2.3.1', 'description': 'SQL injection via crafted search requests when Elasticsearch is enabled.', 'check_type': 'version'},
        {'id': 'CVE-2019-7932', 'severity': 'CRITICAL', 'cvss': 9.0, 'name': 'RCE via Phar Deserialization',
         'affected': 'Magento 1.x <= 1.9.4.1, 2.x < 2.3.1', 'description': 'PHP object injection allowing remote code execution.', 'check_type': 'version'},
    ]

    ADMIN_PATHS = [
        '/admin', '/backend', '/admin123', '/control', '/manager',
        '/administrator', '/admin_area', '/admin_panel', '/cpanel',
        '/magento_admin', '/store_admin', '/manage', '/dashboard',
        '/admin_1', '/admin_2', '/secret', '/hidden_admin',
        '/index.php/admin', '/index.php/backend',
    ]

    GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name description fields { name type { name kind } } } } }"}'

    def __init__(self, callback=None, progress_callback=None):
        self.callback = callback or print
        self.progress_callback = progress_callback
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5', 'Connection': 'keep-alive',
        })
        self.timeout = 15
        self.results = {
            'target': '', 'scan_time': '', 'version': None, 'magento_edition': None,
            'server_info': {}, 'security_headers': {}, 'exposed_paths': [],
            'api_findings': [], 'graphql_findings': [], 'admin_panel': None,
            'cve_matches': [], 'config_issues': [], 'info_disclosure': [],
            'ssl_findings': [], 'recommendations': [],
        }
        self._stop = False

    def stop(self):
        self._stop = True

    def log(self, msg, level='INFO'):
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        if self.callback:
            self.callback(f"[{ts}] [{level:<7}] {msg}")

    def set_progress(self, value, maximum=100):
        if self.progress_callback:
            self.progress_callback(value, maximum)

    def _get(self, url, **kw):
        try: return self.session.get(url, timeout=self.timeout, allow_redirects=True, **kw)
        except: return None

    def _head(self, url, **kw):
        try: return self.session.head(url, timeout=self.timeout, allow_redirects=True, **kw)
        except: return None

    def _post(self, url, **kw):
        try: return self.session.post(url, timeout=self.timeout, **kw)
        except: return None

    def validate_target(self, target_url):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        target_url = target_url.rstrip('/')
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log(f"Validating target: {target_url}")
        resp = self._get(target_url)
        if resp is None and target_url.startswith('https://'):
            target_url = target_url.replace('https://', 'http://')
            self.results['target'] = target_url
            resp = self._get(target_url)
        if resp is None:
            self.log("Target unreachable!", 'ERROR')
            return None
        self.log(f"Target responded: HTTP {resp.status_code}")
        return target_url

    def detect_magento_version(self, target_url):
        self.log("=" * 60)
        self.log("PHASE: Version Detection")
        self.log("=" * 60)
        vi = {'version': None, 'edition': None, 'method': None, 'confidence': 'low'}
        self.log("  Probing /magento_version ...")
        resp = self._get(f"{target_url}/magento_version")
        if resp and resp.status_code == 200 and 'magento' in resp.text.lower():
            vi.update(version=resp.text.strip(), method='/magento_version', confidence='high')
            self.log(f"  >> {vi['version']}", 'FINDING')
        self.log("  Analyzing headers ...")
        resp = self._get(target_url)
        if resp:
            for k, v in resp.headers.items():
                if 'magento' in k.lower():
                    self.log(f"  >> Header: {k}: {v}", 'FINDING')
                    self.results['info_disclosure'].append(f"Header: {k}: {v}")
            srv = resp.headers.get('Server', '')
            xpow = resp.headers.get('X-Powered-By', '')
            if srv: self.results['server_info']['server'] = srv; self.log(f"  Server: {srv}")
            if xpow: self.results['server_info']['x_powered_by'] = xpow; self.log(f"  X-Powered-By: {xpow}"); self.results['info_disclosure'].append(f"X-Powered-By: {xpow}")
            cookies = resp.headers.get('Set-Cookie', '')
            if 'MAGE' in cookies.upper() or 'frontend' in cookies.lower():
                self.log("  >> Magento cookies detected", 'FINDING')
            body = resp.text
            m2 = sum(1 for i in ['requirejs-config.js','mage/cookies','Magento_','data-mage-init','ko.applyBindings','static/version','/pub/static/'] if i in body)
            m1 = sum(1 for i in ['js/varien','skin/frontend','Mage.Cookies','var/uenc','/js/mage/','prototype.js'] if i in body)
            if m2 > m1 and m2 >= 2: vi['edition'] = 'Magento 2.x'; self.log(f"  >> Magento 2 ({m2}/7 indicators)", 'FINDING')
            elif m1 > m2 and m1 >= 2: vi['edition'] = 'Magento 1.x'; self.log(f"  >> Magento 1 ({m1}/6 indicators)", 'FINDING')
            for pat in [r'Magento/([\d.]+)', r'Magento\s+(?:Community|Commerce|Open\s*Source)?\s*(?:Edition)?\s*([\d.]+)',
                        r'magento/product-community-edition.*?([\d.]+)', r'<meta\s+name="generator"\s+content="Magento\s*([\d.]+)"']:
                m = re.search(pat, body, re.IGNORECASE)
                if m: vi.update(version=m.group(1), method='HTML', confidence='medium'); self.log(f"  >> HTML version: {m.group(1)}", 'FINDING'); break
        if vi['edition'] != 'Magento 1.x':
            self.log("  Probing composer.json ...")
            resp = self._get(f"{target_url}/composer.json")
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'magento' in json.dumps(data).lower():
                        self.log("  >> composer.json exposed!", 'VULN')
                        self.results['info_disclosure'].append('composer.json exposed')
                        v = data.get('version', '')
                        if v: vi.update(version=v, method='composer.json', confidence='high')
                except: pass
        resp = self._get(f"{target_url}/pub/static/deployed_version.txt")
        if resp and resp.status_code == 200 and len(resp.text.strip()) < 50:
            self.log(f"  >> deployed_version.txt: {resp.text.strip()}", 'FINDING')
            self.results['info_disclosure'].append(f"deployed_version.txt: {resp.text.strip()}")
        resp = self._get(f"{target_url}/rest/V1/store/storeConfigs")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and data:
                    self.log("  >> REST store config accessible!", 'VULN')
                    self.results['api_findings'].append({'endpoint': '/rest/V1/store/storeConfigs', 'status': 'accessible', 'data_exposed': list(data[0].keys())})
            except: pass
        self.results['version'] = vi.get('version')
        self.results['magento_edition'] = vi.get('edition')
        self.log(f"  Version: {vi.get('version','?')}  Edition: {vi.get('edition','?')}")
        return vi

    def check_security_headers(self, target_url):
        self.log("=" * 60); self.log("PHASE: Security Headers"); self.log("=" * 60)
        resp = self._get(target_url)
        if not resp: self.log("  Unreachable", 'ERROR'); return
        for h in self.SECURITY_HEADERS:
            val = resp.headers.get(h)
            if val:
                self.results['security_headers'][h] = {'present': True, 'value': val}
                self.log(f"  [OK]   {h}: {val}")
            else:
                self.results['security_headers'][h] = {'present': False, 'value': None}
                self.log(f"  [MISS] {h}", 'WARN')
                self.results['recommendations'].append(f"Add header: {h}")

    def scan_paths(self, target_url, threads=10):
        self.log("=" * 60); self.log("PHASE: Path Discovery"); self.log("=" * 60)
        total = len(self.MAGENTO_FINGERPRINTS); completed = 0
        def check(item):
            nonlocal completed
            if self._stop: return None
            path, desc = item; url = f"{target_url}{path}"
            resp = self._head(url)
            if resp is None or resp.status_code == 405: resp = self._get(url)
            completed += 1; self.set_progress(completed, total)
            if resp and resp.status_code == 200:
                return {'path': path, 'description': desc, 'status': 200, 'content_type': resp.headers.get('Content-Type',''), 'content_length': resp.headers.get('Content-Length','?'), 'url': url}
            elif resp and resp.status_code in (301, 302, 403):
                return {'path': path, 'description': desc, 'status': resp.status_code, 'content_type': '', 'content_length': 0, 'url': url}
            return None
        with ThreadPoolExecutor(max_workers=threads) as exe:
            for f in as_completed({exe.submit(check, it): it for it in self.MAGENTO_FINGERPRINTS.items()}):
                if self._stop: break
                r = f.result()
                if r:
                    if r['status'] == 200:
                        self.log(f"  [{r['status']}] {r['path']}  {r['description']}", 'FINDING')
                        self.results['exposed_paths'].append(r)
                        if any(x in r['path'] for x in ['local.xml','env.php','.git','.env','phpinfo','system.log','debug.log','exception.log']):
                            self.log(f"        *** HIGH SEVERITY ***", 'VULN')
                    elif r['status'] == 403: self.log(f"  [{r['status']}] {r['path']}  Forbidden")
        self.log(f"  {len(self.results['exposed_paths'])} accessible paths found")

    def discover_admin_panel(self, target_url):
        self.log("=" * 60); self.log("PHASE: Admin Panel Discovery"); self.log("=" * 60)
        for path in self.ADMIN_PATHS:
            if self._stop: break
            resp = self._get(f"{target_url}{path}")
            if resp and resp.status_code == 200:
                body = resp.text.lower()
                hits = sum(1 for kw in ['login','username','password','sign in','admin','dashboard','magento'] if kw in body)
                if hits >= 2:
                    self.log(f"  >> Admin: {target_url}{path}  (conf:{hits}/7)", 'FINDING')
                    self.results['admin_panel'] = {'url': f"{target_url}{path}", 'path': path, 'confidence': hits}
                    if 'captcha' not in body and 'recaptcha' not in body:
                        self.log("     No CAPTCHA", 'WARN'); self.results['config_issues'].append('Admin: no CAPTCHA')
                    return True
            elif resp and resp.status_code in (301, 302):
                loc = resp.headers.get('Location', '')
                if 'login' in loc.lower() or 'admin' in loc.lower():
                    self.log(f"  >> Admin redirect: {path} -> {loc}", 'FINDING')
                    self.results['admin_panel'] = {'url': f"{target_url}{path}", 'path': path, 'redirect': loc, 'confidence': 4}
                    return True
        self.log("  Not found at common paths"); return False

    def assess_api_security(self, target_url):
        self.log("=" * 60); self.log("PHASE: API Security"); self.log("=" * 60)
        for ep, name in [('/rest/V1/store/storeConfigs','Store Config'), ('/rest/V1/directory/countries','Countries'),
            ('/rest/V1/directory/currency','Currency'), ('/rest/V1/products?searchCriteria[pageSize]=1','Products'),
            ('/rest/V1/categories','Categories'), ('/rest/V1/cmsPage/search?searchCriteria[pageSize]=1','CMS Pages'),
            ('/rest/V1/customers/search?searchCriteria[pageSize]=1','Customers'), ('/rest/V1/orders?searchCriteria[pageSize]=1','Orders'),
            ('/rest/V1/modules','Modules')]:
            if self._stop: break
            resp = self._get(f"{target_url}{ep}")
            if resp:
                if resp.status_code == 200:
                    sz = len(resp.content); sev = 'HIGH' if any(k in name.lower() for k in ('customer','order')) else 'MEDIUM'
                    self.log(f"  [200] {name:<16} OPEN ({sz}B)", 'VULN')
                    self.results['api_findings'].append({'endpoint': ep, 'name': name, 'status': 'accessible', 'response_size': sz, 'severity': sev})
                elif resp.status_code == 401: self.log(f"  [401] {name:<16} Auth required")
                elif resp.status_code == 403: self.log(f"  [403] {name:<16} Forbidden")
        self.log("  --- GraphQL ---")
        gql = f"{target_url}/graphql"
        resp = self._post(gql, data='{"query":"{ storeConfig { store_name base_url copyright } }"}', headers={'Content-Type': 'application/json'})
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if 'data' in data: self.log("  GraphQL active", 'FINDING'); self.results['graphql_findings'].append({'test': 'basic_query', 'result': 'Active', 'severity': 'INFO'})
            except: pass
        resp = self._post(gql, data=self.GRAPHQL_INTROSPECTION, headers={'Content-Type': 'application/json'})
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    types = data['data']['__schema'].get('types', [])
                    self.log(f"  Introspection ON: {len(types)} types", 'VULN')
                    self.results['graphql_findings'].append({'test': 'introspection', 'result': f'{len(types)} types', 'severity': 'HIGH', 'types_count': len(types)})
                    sens = [t['name'] for t in types if any(k in t['name'].lower() for k in ('customer','order','cart','payment','invoice','token','admin'))]
                    if sens: self.log(f"  Sensitive: {', '.join(sens[:8])}", 'WARN'); self.results['graphql_findings'].append({'test': 'sensitive_types', 'result': sens, 'severity': 'MEDIUM'})
            except: pass

    def check_ssl(self, target_url):
        self.log("=" * 60); self.log("PHASE: SSL/TLS"); self.log("=" * 60)
        parsed = urllib.parse.urlparse(target_url); hostname = parsed.hostname; port = parsed.port or 443
        if parsed.scheme != 'https':
            self.log("  No HTTPS!", 'VULN'); self.results['ssl_findings'].append({'issue': 'No HTTPS', 'severity': 'HIGH'}); return
        try:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                    self.log(f"  Protocol: {ss.version()}"); self.log(f"  Cipher: {ss.cipher()[0]} ({ss.cipher()[2]}-bit)")
                    if ss.cipher()[2] < 128: self.log("  Weak cipher!", 'WARN'); self.results['ssl_findings'].append({'issue': f'Weak: {ss.cipher()[2]}-bit', 'severity': 'MEDIUM'})
                    if ss.version() in ('TLSv1', 'TLSv1.1'): self.log(f"  Deprecated TLS!", 'VULN'); self.results['ssl_findings'].append({'issue': f'Deprecated {ss.version()}', 'severity': 'HIGH'})
            try:
                vc = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as s:
                    with vc.wrap_socket(s, server_hostname=hostname) as ss: cert = ss.getpeercert(); self.log(f"  Valid until: {cert.get('notAfter','?')}"); self.log("  Cert: OK")
            except ssl.SSLCertVerificationError as e: self.log(f"  Cert FAIL: {e}", 'WARN'); self.results['ssl_findings'].append({'issue': str(e)[:80], 'severity': 'MEDIUM'})
        except Exception as e: self.log(f"  SSL error: {e}", 'ERROR')

    def check_known_cves(self, target_url):
        self.log("=" * 60); self.log("PHASE: CVE Assessment"); self.log("=" * 60)
        ver = self.results.get('version')
        for cve in self.KNOWN_CVES:
            if self._stop: break
            if cve['check_type'] == 'endpoint':
                ep = cve.get('endpoint', '')
                if ep:
                    resp = self._get(f"{target_url}{ep}")
                    if resp and resp.status_code == 200:
                        self.log(f"  {cve['id']} [{cve['severity']}] CVSS:{cve['cvss']}  {cve['name']}", 'VULN')
                        self.results['cve_matches'].append({**cve, 'match_method': 'endpoint', 'confidence': 'medium'})
            elif cve['check_type'] == 'version' and ver:
                self.results['cve_matches'].append({**cve, 'match_method': 'version', 'detected_version': ver, 'confidence': 'verify'})
                self.log(f"  {cve['id']} [{cve['severity']}] {cve['name']} -- verify", 'WARN')
        if not self.results['cve_matches']: self.log("  No matches (not proof of safety)")

    def check_configuration(self, target_url):
        self.log("=" * 60); self.log("PHASE: Configuration"); self.log("=" * 60)
        for d in ['/media/', '/var/', '/pub/media/', '/pub/static/', '/static/']:
            if self._stop: break
            resp = self._get(f"{target_url}{d}")
            if resp and resp.status_code == 200 and ('index of' in resp.text.lower() or '<pre>' in resp.text.lower()):
                self.log(f"  Dir listing: {d}", 'VULN'); self.results['config_issues'].append(f'Dir listing: {d}')
        for df in ['/phpinfo.php', '/info.php', '/test.php', '/adminer.php', '/phpmyadmin/']:
            resp = self._get(f"{target_url}{df}")
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                self.log(f"  Debug file: {df}", 'VULN'); self.results['config_issues'].append(f'Debug: {df}')
        resp = self._get(f"{target_url}/.git/HEAD")
        if resp and resp.status_code == 200 and 'ref:' in resp.text:
            self.log("  *** .git exposed! ***", 'VULN'); self.results['config_issues'].append('.git exposed')
        resp = self._get(f"{target_url}/.env")
        if resp and resp.status_code == 200 and '=' in resp.text and len(resp.text) > 10:
            self.log("  *** .env exposed! ***", 'VULN'); self.results['config_issues'].append('.env exposed')
        for w in ['/downloader/', '/setup/', '/update/']:
            resp = self._get(f"{target_url}{w}")
            if resp and resp.status_code == 200 and len(resp.text) > 500:
                self.log(f"  Wizard: {w}", 'VULN'); self.results['config_issues'].append(f'Wizard: {w}')
        resp = self._get(target_url, headers={'Origin': 'https://evil.com'})
        if resp:
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            if acao == '*': self.log("  CORS wildcard", 'VULN'); self.results['config_issues'].append('CORS: *')
            elif 'evil.com' in acao: self.log("  CORS reflects origin", 'VULN'); self.results['config_issues'].append('CORS: reflects')

    def generate_recommendations(self):
        self.log("=" * 60); self.log("PHASE: Recommendations"); self.log("=" * 60)
        r = self.results['recommendations']
        if self.results['exposed_paths']: r.append("Restrict sensitive file access")
        if self.results['config_issues']: r.append("Fix all configuration issues")
        if any(f.get('severity') == 'HIGH' for f in self.results['api_findings']): r.append("Authenticate API endpoints")
        if any(f['test'] == 'introspection' for f in self.results['graphql_findings']): r.append("Disable GraphQL introspection")
        if self.results['cve_matches']: r.append("Apply security patches for flagged CVEs")
        if self.results.get('admin_panel'): r.append("Change admin URL"); r.append("IP-whitelist admin"); r.append("Enable admin 2FA")
        r.append("Keep Magento updated"); r.append("Deploy WAF"); r.append("Enable Magento Security Scan")
        for i, item in enumerate(r, 1): self.log(f"  {i:>2}. {item}")

    def run_full_scan(self, target_url, scan_options=None):
        self._stop = False; scan_options = scan_options or {}
        self.log("=" * 60); self.log("  MAGENTO SECURITY ASSESSMENT TOOL"); self.log("  Tester Present - testerpresent.com.au"); self.log("=" * 60)
        target = self.validate_target(target_url)
        if not target: return self.results
        phases = []
        if scan_options.get('version_detect', True): phases.append(('Ver', lambda: self.detect_magento_version(target)))
        if scan_options.get('security_headers', True): phases.append(('Hdr', lambda: self.check_security_headers(target)))
        if scan_options.get('path_scan', True): phases.append(('Path', lambda: self.scan_paths(target, threads=scan_options.get('threads', 10))))
        if scan_options.get('admin_discovery', True): phases.append(('Admin', lambda: self.discover_admin_panel(target)))
        if scan_options.get('api_security', True): phases.append(('API', lambda: self.assess_api_security(target)))
        if scan_options.get('ssl_check', True): phases.append(('SSL', lambda: self.check_ssl(target)))
        if scan_options.get('cve_check', True): phases.append(('CVE', lambda: self.check_known_cves(target)))
        if scan_options.get('config_check', True): phases.append(('Cfg', lambda: self.check_configuration(target)))
        tot = len(phases) + 1
        for i, (n, fn) in enumerate(phases):
            if self._stop: self.log("Aborted.", 'WARN'); break
            self.set_progress(i, tot); fn()
        if not self._stop: self.set_progress(tot-1, tot); self.generate_recommendations()
        self.set_progress(tot, tot)
        self.log(""); self.log("=" * 60); self.log("  SUMMARY"); self.log("=" * 60)
        self.log(f"  Target:   {target}"); self.log(f"  Version:  {self.results.get('version','?')}")
        self.log(f"  Edition:  {self.results.get('magento_edition','?')}")
        self.log(f"  Paths:    {len(self.results['exposed_paths'])}"); self.log(f"  API:      {len(self.results['api_findings'])}")
        self.log(f"  GraphQL:  {len(self.results['graphql_findings'])}"); self.log(f"  Config:   {len(self.results['config_issues'])}")
        self.log(f"  InfoLeak: {len(self.results['info_disclosure'])}"); self.log(f"  SSL:      {len(self.results['ssl_findings'])}")
        self.log(f"  CVEs:     {len(self.results['cve_matches'])}"); self.log(f"  Recs:     {len(self.results['recommendations'])}")
        self.log(f"  Done:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return self.results


# ══════════════════════════════════════════════════════════════════════
# GUI - STOCK TKINTER, ENGINEERING AESTHETIC
# ══════════════════════════════════════════════════════════════════════

class MagentoPenTestApp:
    BG       = '#e0e0e0'
    BG_FRAME = '#d4d4d4'
    BG_WHITE = '#ffffff'
    FG       = '#1a1a1a'
    FG_DIM   = '#555555'
    COL_BLUE = '#336699'
    COL_BAR  = '#4477aa'
    COL_ERR  = '#cc0000'
    COL_WARN = '#cc6600'

    def __init__(self, root):
        self.root = root
        self.root.title("MSAT v1.0 | Magento Security Assessment Tool | Tester Present")
        self.root.geometry("1320x870")
        self.root.minsize(1050, 680)
        self.root.configure(bg=self.BG)
        self.root.option_add('*tearOff', False)
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        self.FNT_MONO   = ('Consolas', 9)
        self.FNT_MONO_B = ('Consolas', 9, 'bold')
        self.FNT_UI     = ('Segoe UI', 9)
        self.FNT_UI_B   = ('Segoe UI', 9, 'bold')
        self.FNT_UI_S   = ('Segoe UI', 8)
        self.FNT_TITLE  = ('Segoe UI', 10, 'bold')
        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

    def _build_menu(self):
        mb = tk.Menu(self.root)
        self.root.config(menu=mb)
        fm = tk.Menu(mb); mb.add_cascade(label="File", menu=fm)
        fm.add_command(label="Export JSON...", command=self.export_json, accelerator="Ctrl+J")
        fm.add_command(label="Export CSV...", command=self.export_csv)
        fm.add_command(label="Export Report...", command=self.export_report, accelerator="Ctrl+R")
        fm.add_separator(); fm.add_command(label="Exit", command=self.root.quit)
        sm = tk.Menu(mb); mb.add_cascade(label="Scan", menu=sm)
        sm.add_command(label="Start Scan", command=self.start_scan, accelerator="F5")
        sm.add_command(label="Stop Scan", command=self.stop_scan, accelerator="Esc")
        sm.add_separator(); sm.add_command(label="Clear Console", command=self.clear_console)
        hm = tk.Menu(mb); mb.add_cascade(label="Help", menu=hm)
        hm.add_command(label="About MSAT", command=self._show_about)
        self.root.bind('<F5>', lambda e: self.start_scan())
        self.root.bind('<Escape>', lambda e: self.stop_scan())

    def _build_toolbar(self):
        tb = tk.Frame(self.root, bg=self.BG_FRAME, bd=1, relief='groove')
        tb.pack(fill='x', padx=4, pady=(4, 0))
        r1 = tk.Frame(tb, bg=self.BG_FRAME); r1.pack(fill='x', padx=6, pady=4)
        tk.Label(r1, text="Target URL:", font=self.FNT_UI_B, bg=self.BG_FRAME).pack(side='left')
        self.target_var = tk.StringVar(value="https://")
        self.target_entry = tk.Entry(r1, textvariable=self.target_var, font=self.FNT_MONO, width=60, relief='sunken', bd=2)
        self.target_entry.pack(side='left', padx=(6, 8), ipady=2)
        self.target_entry.bind('<Return>', lambda e: self.start_scan())
        self.btn_scan = tk.Button(r1, text=" Start Scan (F5) ", font=self.FNT_UI_B, command=self.start_scan, relief='raised', bd=2, padx=8)
        self.btn_scan.pack(side='left', padx=(0, 4))
        self.btn_stop = tk.Button(r1, text=" Stop ", font=self.FNT_UI, command=self.stop_scan, relief='raised', bd=2, state='disabled', padx=8)
        self.btn_stop.pack(side='left', padx=(0, 4))
        tk.Frame(r1, width=2, bg='#999999').pack(side='left', fill='y', padx=8, pady=2)
        tk.Label(r1, text="Threads:", font=self.FNT_UI, bg=self.BG_FRAME, fg=self.FG_DIM).pack(side='left')
        self.threads_var = tk.IntVar(value=10)
        tk.Spinbox(r1, from_=1, to=30, textvariable=self.threads_var, width=3, font=self.FNT_MONO, relief='sunken', bd=2).pack(side='left', padx=(2, 8))
        tk.Label(r1, text="Timeout:", font=self.FNT_UI, bg=self.BG_FRAME, fg=self.FG_DIM).pack(side='left')
        self.timeout_var = tk.IntVar(value=15)
        tk.Spinbox(r1, from_=5, to=60, textvariable=self.timeout_var, width=3, font=self.FNT_MONO, relief='sunken', bd=2).pack(side='left', padx=(2, 0))
        pf = tk.Frame(tb, bg=self.BG_FRAME); pf.pack(fill='x', padx=6, pady=(0, 4))
        tk.Label(pf, text="Progress:", font=self.FNT_UI_S, bg=self.BG_FRAME, fg=self.FG_DIM).pack(side='left')
        self.progress_canvas = tk.Canvas(pf, height=14, bg='#c0c0c0', highlightthickness=1, highlightbackground='#999999')
        self.progress_canvas.pack(side='left', fill='x', expand=True, padx=(4, 8))
        self.progress_label = tk.Label(pf, text="0%", font=self.FNT_MONO, bg=self.BG_FRAME, fg=self.FG_DIM, width=5)
        self.progress_label.pack(side='left')

    def _build_body(self):
        self.main_pw = tk.PanedWindow(self.root, orient='horizontal', bg=self.BG, sashwidth=5, sashrelief='raised')
        self.main_pw.pack(fill='both', expand=True, padx=4, pady=4)
        left = tk.Frame(self.main_pw, bg=self.BG_FRAME, bd=1, relief='groove')
        self.main_pw.add(left, width=220, minsize=180)
        tk.Label(left, text=" Scan Modules", font=self.FNT_TITLE, bg=self.COL_BLUE, fg='white', anchor='w', padx=4).pack(fill='x')
        of = tk.Frame(left, bg=self.BG_FRAME); of.pack(fill='both', expand=True, padx=4, pady=4)
        self.opt_vars = {}
        for key, label in [('version_detect','Version Detection'), ('security_headers','Security Headers'),
            ('path_scan','Path Discovery'), ('admin_discovery','Admin Panel'), ('api_security','API Security'),
            ('ssl_check','SSL/TLS Analysis'), ('cve_check','CVE Assessment'), ('config_check','Configuration')]:
            v = tk.BooleanVar(value=True); self.opt_vars[key] = v
            tk.Checkbutton(of, text=label, variable=v, font=self.FNT_UI, bg=self.BG_FRAME, anchor='w', selectcolor=self.BG_WHITE).pack(fill='x', padx=2, pady=1)
        tk.Frame(of, height=1, bg='#aaaaaa').pack(fill='x', pady=6)
        tk.Button(of, text="Select All", font=self.FNT_UI_S, command=lambda: [v.set(True) for v in self.opt_vars.values()], relief='groove', bd=1).pack(fill='x', padx=2, pady=1)
        tk.Button(of, text="Select None", font=self.FNT_UI_S, command=lambda: [v.set(False) for v in self.opt_vars.values()], relief='groove', bd=1).pack(fill='x', padx=2, pady=1)
        inf = tk.LabelFrame(left, text=" Target Info ", font=self.FNT_UI_S, bg=self.BG_FRAME, fg=self.FG_DIM, relief='groove')
        inf.pack(fill='x', padx=4, pady=4)
        self.info_labels = {}
        for f in ['Version', 'Edition', 'Server', 'Admin']:
            row = tk.Frame(inf, bg=self.BG_FRAME); row.pack(fill='x', padx=2, pady=1)
            tk.Label(row, text=f"{f}:", font=self.FNT_UI_S, bg=self.BG_FRAME, fg=self.FG_DIM, width=8, anchor='w').pack(side='left')
            lbl = tk.Label(row, text="--", font=self.FNT_MONO, bg=self.BG_FRAME, anchor='w'); lbl.pack(side='left', fill='x', expand=True)
            self.info_labels[f] = lbl
        right = tk.Frame(self.main_pw, bg=self.BG); self.main_pw.add(right, minsize=600)
        self.notebook = ttk.Notebook(right); self.notebook.pack(fill='both', expand=True)
        self._build_console_tab(); self._build_findings_tab(); self._build_cve_tab(); self._build_report_tab()

    def _build_console_tab(self):
        frame = tk.Frame(self.notebook, bg=self.BG); self.notebook.add(frame, text='  Console Output  ')
        ctb = tk.Frame(frame, bg=self.BG_FRAME); ctb.pack(fill='x')
        tk.Label(ctb, text=" Scan Log", font=self.FNT_UI_B, bg=self.BG_FRAME).pack(side='left', padx=4, pady=2)
        tk.Button(ctb, text="Clear", font=self.FNT_UI_S, command=self.clear_console, relief='groove', bd=1).pack(side='right', padx=4, pady=2)
        self.line_count_label = tk.Label(ctb, text="Lines: 0", font=self.FNT_UI_S, bg=self.BG_FRAME, fg=self.FG_DIM)
        self.line_count_label.pack(side='right', padx=4)
        cf = tk.Frame(frame, bd=2, relief='sunken'); cf.pack(fill='both', expand=True, padx=4, pady=4)
        self.console = tk.Text(cf, wrap='word', font=self.FNT_MONO, bg='#1e1e1e', fg='#cccccc', insertbackground='#ffffff', selectbackground='#264f78', relief='flat', padx=6, pady=4, state='disabled')
        sy = tk.Scrollbar(cf, orient='vertical', command=self.console.yview); self.console.configure(yscrollcommand=sy.set)
        sy.pack(side='right', fill='y'); self.console.pack(side='left', fill='both', expand=True)
        self.console.tag_configure('INFO', foreground='#cccccc')
        self.console.tag_configure('FINDING', foreground='#57a0d3')
        self.console.tag_configure('VULN', foreground='#ff5555')
        self.console.tag_configure('WARN', foreground='#e5a700')
        self.console.tag_configure('ERROR', foreground='#ff3333')
        self.console.tag_configure('HEAD', foreground='#7799bb', font=self.FNT_MONO_B)
        self._console_lines = 0

    def _build_findings_tab(self):
        frame = tk.Frame(self.notebook, bg=self.BG); self.notebook.add(frame, text='  Findings  ')
        sb = tk.Frame(frame, bg=self.BG_FRAME, bd=1, relief='groove'); sb.pack(fill='x', padx=4, pady=(4, 0))
        self.summary_labels = {}
        for l in ['Total', 'High', 'Medium', 'Low', 'Info']:
            f = tk.Frame(sb, bg=self.BG_FRAME); f.pack(side='left', padx=8, pady=3)
            tk.Label(f, text=l+":", font=self.FNT_UI_S, bg=self.BG_FRAME, fg=self.FG_DIM).pack(side='left')
            v = tk.Label(f, text="0", font=self.FNT_MONO_B, bg=self.BG_FRAME); v.pack(side='left', padx=(2, 0))
            self.summary_labels[l] = v
        tf = tk.Frame(frame, bd=2, relief='sunken'); tf.pack(fill='both', expand=True, padx=4, pady=4)
        cols = ('cat', 'sev', 'finding', 'detail')
        self.findings_tree = ttk.Treeview(tf, columns=cols, show='headings', height=20)
        self.findings_tree.heading('cat', text='Category'); self.findings_tree.heading('sev', text='Severity')
        self.findings_tree.heading('finding', text='Finding'); self.findings_tree.heading('detail', text='Details')
        self.findings_tree.column('cat', width=130); self.findings_tree.column('sev', width=70)
        self.findings_tree.column('finding', width=380); self.findings_tree.column('detail', width=350)
        sy = tk.Scrollbar(tf, orient='vertical', command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=sy.set); sy.pack(side='right', fill='y')
        self.findings_tree.pack(side='left', fill='both', expand=True)
        self.findings_tree.tag_configure('HIGH', foreground=self.COL_ERR)
        self.findings_tree.tag_configure('MEDIUM', foreground=self.COL_WARN)
        self.findings_tree.tag_configure('LOW', foreground=self.FG_DIM)
        self.findings_tree.tag_configure('INFO', foreground=self.COL_BLUE)

    def _build_cve_tab(self):
        frame = tk.Frame(self.notebook, bg=self.BG); self.notebook.add(frame, text='  CVE Reference  ')
        tk.Label(frame, text=" Known Magento CVEs", font=self.FNT_UI_B, bg=self.BG_FRAME, anchor='w').pack(fill='x', padx=4, pady=(4, 0))
        tf = tk.Frame(frame, bd=2, relief='sunken'); tf.pack(fill='both', expand=True, padx=4, pady=4)
        cols = ('id', 'sev', 'cvss', 'name', 'affected')
        self.cve_tree = ttk.Treeview(tf, columns=cols, show='headings', height=15)
        for c, t in [('id','CVE ID'), ('sev','Severity'), ('cvss','CVSS'), ('name','Vulnerability'), ('affected','Affected')]:
            self.cve_tree.heading(c, text=t)
        self.cve_tree.column('id', width=140); self.cve_tree.column('sev', width=75); self.cve_tree.column('cvss', width=50)
        self.cve_tree.column('name', width=300); self.cve_tree.column('affected', width=280)
        sy = tk.Scrollbar(tf, orient='vertical', command=self.cve_tree.yview)
        self.cve_tree.configure(yscrollcommand=sy.set); sy.pack(side='right', fill='y')
        self.cve_tree.pack(side='left', fill='both', expand=True)
        self.cve_tree.tag_configure('CRITICAL', foreground=self.COL_ERR); self.cve_tree.tag_configure('HIGH', foreground=self.COL_WARN)
        for c in MagentoScanner.KNOWN_CVES:
            tag = c['severity'] if c['severity'] in ('CRITICAL', 'HIGH') else ''
            self.cve_tree.insert('', 'end', values=(c['id'], c['severity'], c['cvss'], c['name'], c['affected']), tags=(tag,))
        det = tk.LabelFrame(frame, text=" Details ", font=self.FNT_UI_S, bg=self.BG_FRAME, relief='groove')
        det.pack(fill='x', padx=4, pady=(0, 4))
        self.cve_detail = tk.Text(det, height=4, font=self.FNT_MONO, bg=self.BG_WHITE, relief='sunken', bd=1, wrap='word', state='disabled')
        self.cve_detail.pack(fill='x', padx=4, pady=4)
        def on_sel(e):
            sel = self.cve_tree.selection()
            if sel:
                cid = self.cve_tree.item(sel[0])['values'][0]
                for c in MagentoScanner.KNOWN_CVES:
                    if c['id'] == cid:
                        self.cve_detail.configure(state='normal'); self.cve_detail.delete('1.0', 'end')
                        self.cve_detail.insert('1.0', f"{c['id']}  [{c['severity']}]  CVSS: {c['cvss']}\nAffected: {c['affected']}\n{c['description']}")
                        self.cve_detail.configure(state='disabled'); break
        self.cve_tree.bind('<<TreeviewSelect>>', on_sel)

    def _build_report_tab(self):
        frame = tk.Frame(self.notebook, bg=self.BG); self.notebook.add(frame, text='  Report  ')
        tb = tk.Frame(frame, bg=self.BG_FRAME); tb.pack(fill='x')
        tk.Label(tb, text=" Assessment Report", font=self.FNT_UI_B, bg=self.BG_FRAME).pack(side='left', padx=4, pady=2)
        tk.Button(tb, text="Export...", font=self.FNT_UI_S, command=self.export_report, relief='groove', bd=1).pack(side='right', padx=4, pady=2)
        rf = tk.Frame(frame, bd=2, relief='sunken'); rf.pack(fill='both', expand=True, padx=4, pady=4)
        self.report_text = tk.Text(rf, wrap='word', font=self.FNT_MONO, bg=self.BG_WHITE, relief='flat', padx=8, pady=6, state='disabled')
        sy = tk.Scrollbar(rf, orient='vertical', command=self.report_text.yview); self.report_text.configure(yscrollcommand=sy.set)
        sy.pack(side='right', fill='y'); self.report_text.pack(side='left', fill='both', expand=True)

    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=self.BG_FRAME, bd=1, relief='sunken'); sb.pack(fill='x', padx=4, pady=(0, 4))
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(sb, textvariable=self.status_var, font=self.FNT_UI_S, bg=self.BG_FRAME, fg=self.FG_DIM, anchor='w').pack(side='left', padx=4, pady=1)
        tk.Label(sb, text="Tester Present | testerpresent.com.au", font=self.FNT_UI_S, bg=self.BG_FRAME, fg='#888888').pack(side='right', padx=4)

    def console_write(self, text):
        def _w():
            self.console.configure(state='normal')
            tag = 'INFO'
            if '[FINDING]' in text: tag = 'FINDING'
            elif '[VULN' in text: tag = 'VULN'
            elif '[WARN' in text: tag = 'WARN'
            elif '[ERROR' in text: tag = 'ERROR'
            elif '===' in text or 'PHASE:' in text or 'SUMMARY' in text: tag = 'HEAD'
            self.console.insert('end', text + '\n', tag); self.console.see('end')
            self.console.configure(state='disabled')
            self._console_lines += 1; self.line_count_label.config(text=f"Lines: {self._console_lines}")
        self.root.after(0, _w)

    def update_progress(self, value, maximum):
        def _u():
            pct = (value / maximum * 100) if maximum > 0 else 0
            self.progress_label.config(text=f"{int(pct)}%")
            self.progress_canvas.update_idletasks()
            w = self.progress_canvas.winfo_width(); h = self.progress_canvas.winfo_height()
            self.progress_canvas.delete('all')
            fw = int(w * pct / 100)
            if fw > 0: self.progress_canvas.create_rectangle(0, 0, fw, h, fill=self.COL_BAR, outline='')
            self.progress_canvas.create_text(w//2, h//2, text=f"{int(pct)}%", font=('Consolas', 7), fill='#333333')
            self.status_var.set(f"Scanning... {int(pct)}%")
        self.root.after(0, _u)

    def clear_console(self):
        self.console.configure(state='normal'); self.console.delete('1.0', 'end'); self.console.configure(state='disabled')
        self._console_lines = 0; self.line_count_label.config(text="Lines: 0")

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target or target in ('https://', 'http://'): messagebox.showwarning("MSAT", "Enter a target URL."); return
        if not messagebox.askyesno("Authorization", f"Target: {target}\n\nConfirm written authorization to test."): return
        self.is_scanning = True; self.btn_scan.configure(state='disabled'); self.btn_stop.configure(state='normal')
        self.clear_console()
        for item in self.findings_tree.get_children(): self.findings_tree.delete(item)
        for lbl in self.info_labels.values(): lbl.config(text="--")
        for lbl in self.summary_labels.values(): lbl.config(text="0")
        opts = {k: v.get() for k, v in self.opt_vars.items()}; opts['threads'] = self.threads_var.get()
        self.scanner = MagentoScanner(callback=self.console_write, progress_callback=self.update_progress)
        self.scanner.timeout = self.timeout_var.get()
        def _run():
            try:
                results = self.scanner.run_full_scan(target, opts)
                self.root.after(0, lambda: self._on_complete(results))
            except Exception as e:
                self.console_write(f"[ERROR] {e}"); self.root.after(0, self._on_error)
        self.scan_thread = threading.Thread(target=_run, daemon=True); self.scan_thread.start()

    def stop_scan(self):
        if self.scanner: self.scanner.stop()
        self.status_var.set("Stopped"); self.btn_scan.configure(state='normal'); self.btn_stop.configure(state='disabled'); self.is_scanning = False

    def _on_complete(self, results):
        self.is_scanning = False; self.btn_scan.configure(state='normal'); self.btn_stop.configure(state='disabled')
        self.status_var.set(f"Complete | {len(results.get('exposed_paths',[]))} paths, {len(results.get('config_issues',[]))} issues")
        self.info_labels['Version'].config(text=results.get('version') or '?')
        self.info_labels['Edition'].config(text=results.get('magento_edition') or '?')
        self.info_labels['Server'].config(text=results.get('server_info', {}).get('server', '?'))
        ap = results.get('admin_panel'); self.info_labels['Admin'].config(text=ap['path'] if ap else 'N/F')
        self._populate_findings(results); self._generate_report(results)
        self.progress_label.config(text="100%")
        self.progress_canvas.update_idletasks()
        w = self.progress_canvas.winfo_width(); h = self.progress_canvas.winfo_height()
        self.progress_canvas.delete('all')
        self.progress_canvas.create_rectangle(0, 0, w, h, fill='#55aa55', outline='')
        self.progress_canvas.create_text(w//2, h//2, text="DONE", font=('Consolas', 7, 'bold'), fill='white')

    def _on_error(self):
        self.is_scanning = False; self.btn_scan.configure(state='normal'); self.btn_stop.configure(state='disabled'); self.status_var.set("Error")

    def _populate_findings(self, results):
        for item in self.findings_tree.get_children(): self.findings_tree.delete(item)
        counts = {'Total': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        def add(cat, sev, finding, detail=''):
            self.findings_tree.insert('', 'end', values=(cat, sev, finding, detail), tags=(sev,))
            counts['Total'] += 1
            if sev in counts: counts[sev] += 1
        for p in results.get('exposed_paths', []):
            sev = 'HIGH' if any(s in p['path'] for s in ['local.xml','env.php','.git','.env','phpinfo','system.log']) else 'Medium' if any(s in p['path'] for s in ['composer','setup','downloader','api']) else 'Low'
            add('Exposed Path', sev, p['path'], p['description'])
        for a in results.get('api_findings', []): add('API', a.get('severity', 'Medium'), a['endpoint'], a.get('name', ''))
        for g in results.get('graphql_findings', []): r = g['result'] if isinstance(g['result'], str) else str(g['result'])[:80]; add('GraphQL', g.get('severity', 'Info'), g['test'], r)
        for i in results.get('config_issues', []): add('Config', 'HIGH', i)
        for i in results.get('info_disclosure', []): add('InfoLeak', 'Medium', i)
        for s in results.get('ssl_findings', []): add('SSL', s.get('severity', 'Medium'), s.get('issue', ''))
        for h, d in results.get('security_headers', {}).items():
            if not d.get('present'): add('Header', 'Low', f'Missing: {h}')
        for k, v in counts.items():
            if k in self.summary_labels: self.summary_labels[k].config(text=str(v))

    def _generate_report(self, results):
        self.report_text.configure(state='normal'); self.report_text.delete('1.0', 'end')
        r = ["=" * 72, "  MAGENTO SECURITY ASSESSMENT REPORT", "  Tester Present - testerpresent.com.au", "=" * 72,
             f"  Target:    {results.get('target', 'N/A')}", f"  Scan:      {results.get('scan_time', 'N/A')}",
             f"  Version:   {results.get('version', '?')}", f"  Edition:   {results.get('magento_edition', '?')}", "",
             "-" * 72, "  SUMMARY", "-" * 72]
        tot = sum(len(results.get(k, [])) for k in ['exposed_paths', 'api_findings', 'config_issues', 'info_disclosure', 'ssl_findings'])
        r.append(f"  Total Findings: {tot}")
        for k, n in [('exposed_paths','Paths'), ('api_findings','API'), ('config_issues','Config'), ('info_disclosure','InfoLeak'), ('ssl_findings','SSL'), ('cve_matches','CVE')]:
            r.append(f"    {n}: {len(results.get(k, []))}")
        r += ["", "-" * 72, "  SECURITY HEADERS", "-" * 72]
        for h, d in results.get('security_headers', {}).items():
            st = "[OK]  " if d.get('present') else "[MISS]"; r.append(f"  {st} {h}: {d.get('value', '')}")
        if results.get('exposed_paths'):
            r += ["", "-" * 72, "  EXPOSED PATHS", "-" * 72]
            for p in results['exposed_paths']: r.append(f"  [{p['status']}] {p['path']}  {p['description']}")
        if results.get('api_findings'):
            r += ["", "-" * 72, "  API FINDINGS", "-" * 72]
            for a in results['api_findings']: r.append(f"  [{a.get('severity','?')}] {a['endpoint']}  {a.get('name','')}")
        if results.get('config_issues'):
            r += ["", "-" * 72, "  CONFIG ISSUES", "-" * 72]
            for i in results['config_issues']: r.append(f"  * {i}")
        if results.get('cve_matches'):
            r += ["", "-" * 72, "  CVE MATCHES (Verify)", "-" * 72]
            for c in results['cve_matches']: r.append(f"  {c['id']} [{c['severity']}] CVSS:{c['cvss']}  {c['name']}"); r.append(f"    {c['description']}"); r.append("")
        if results.get('recommendations'):
            r += ["-" * 72, "  RECOMMENDATIONS", "-" * 72]
            for i, rec in enumerate(results['recommendations'], 1): r.append(f"  {i:>2}. {rec}")
        r += ["", "=" * 72, "  END OF REPORT", "=" * 72]
        self.report_text.insert('1.0', '\n'.join(r)); self.report_text.configure(state='disabled')

    def export_json(self):
        if not self.scanner or not self.scanner.results.get('target'): messagebox.showinfo("MSAT", "No data."); return
        fp = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json')], initialfile=f"msat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if fp:
            with open(fp, 'w') as f: json.dump(self.scanner.results, f, indent=2, default=str)
            messagebox.showinfo("MSAT", f"Saved:\n{fp}")

    def export_csv(self):
        if not self.scanner or not self.scanner.results.get('target'): messagebox.showinfo("MSAT", "No data."); return
        fp = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')], initialfile=f"msat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if fp:
            with open(fp, 'w', newline='') as f:
                w = csv.writer(f); w.writerow(['Category', 'Severity', 'Finding', 'Details'])
                for item in self.findings_tree.get_children(): w.writerow(self.findings_tree.item(item)['values'])
            messagebox.showinfo("MSAT", f"Saved:\n{fp}")

    def export_report(self):
        if not self.scanner or not self.scanner.results.get('target'): messagebox.showinfo("MSAT", "No data."); return
        fp = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text', '*.txt')], initialfile=f"msat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if fp:
            self.report_text.configure(state='normal'); c = self.report_text.get('1.0', 'end'); self.report_text.configure(state='disabled')
            with open(fp, 'w') as f: f.write(c)
            messagebox.showinfo("MSAT", f"Saved:\n{fp}")

    def _show_about(self):
        messagebox.showinfo("About MSAT",
            "MSAT v1.0\nMagento Security Assessment Tool\n\nTester Present\ntesterpresent.com.au\n\n"
            "10 scan phases | 11 CVE references\nJSON / CSV / Text export\n\nAuthorized testing only.")


def main():
    root = tk.Tk()
    app = MagentoPenTestApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
