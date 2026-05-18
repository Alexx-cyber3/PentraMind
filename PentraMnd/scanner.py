import socket
import requests
import time
import re
from bs4 import BeautifulSoup

class SecurityScanner:
    def __init__(self):
        """
        Initializes the security scanner with a pre-defined knowledge base
        of common web vulnerabilities, remediation strategies, and OWASP mappings.
        """
        self.knowledge_base = {
            "Missing Content-Security-Policy (CSP)": {
                "summary": "The application lacks a Content-Security-Policy, which is a critical defense against Cross-Site Scripting (XSS) and injection attacks.",
                "remediation": "Implement a 'Content-Security-Policy' header. Start with 'default-src self' and gradually allow necessary external resources.",
                "exploitation": "Inject a malicious script tag <script>alert('XSS')</script> into an input field or URL parameter. Without CSP, the browser will execute it.",
                "severity": "High",
                "owasp": "A03:2021-Injection",
                "patches": {
                    "nginx": "add_header Content-Security-Policy \"default-src 'self';\";",
                    "apache": "Header set Content-Security-Policy \"default-src 'self';\""
                }
            },
            "Missing X-Frame-Options": {
                "summary": "Without X-Frame-Options, your site can be embedded in an iframe on a malicious domain, leading to Clickjacking attacks.",
                "remediation": "Add 'X-Frame-Options: SAMEORIGIN' or 'DENY' to your server's HTTP response headers.",
                "exploitation": "Create a malicious page that iframes the target site with opacity: 0 and overlays an enticing button to trick users into clicking actions on the target site.",
                "severity": "Medium",
                "owasp": "A04:2021-Insecure Design",
                "patches": {
                    "nginx": "add_header X-Frame-Options \"SAMEORIGIN\";",
                    "apache": "Header set X-Frame-Options \"SAMEORIGIN\""
                }
            },
            "Missing Strict-Transport-Security": {
                "summary": "HSTS is not enabled, meaning the browser might attempt to connect via insecure HTTP before redirecting to HTTPS.",
                "remediation": "Enable HSTS by adding the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                "exploitation": "Perform an SSL Stripping attack using tools like bettercap to intercept the initial HTTP request and prevent the upgrade to HTTPS.",
                "severity": "Medium",
                "owasp": "A05:2021-Security Misconfiguration",
                "patches": {
                    "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                    "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
                }
            },
            "Missing X-Content-Type-Options": {
                "summary": "The lack of 'nosniff' directive allows browsers to guess MIME types, which can lead to script injection via uploaded files.",
                "remediation": "Add the 'X-Content-Type-Options: nosniff' header to all responses.",
                "exploitation": "Upload a file with a safe extension (e.g., .jpg) containing malicious JavaScript and trick the browser into executing it as a script.",
                "severity": "Low",
                "owasp": "A05:2021-Security Misconfiguration",
                "patches": {
                    "nginx": "add_header X-Content-Type-Options \"nosniff\";",
                    "apache": "Header set X-Content-Type-Options \"nosniff\""
                }
            },
            "Exposed HTML Forms": {
                "summary": "Detected interactive input fields. These are potential entry points for SQL Injection, XSS, and CSRF if not properly protected.",
                "remediation": "Ensure all form inputs use server-side validation, prepared statements for DB queries, and CSRF tokens.",
                "exploitation": "Test for SQL Injection using a single quote ' or a payload like ' OR '1'='1. Test for XSS using <svg/onload=alert(1)>.",
                "severity": "Info",
                "owasp": "A01:2021-Broken Access Control",
                "patches": {
                    "python": "# Use parameterized queries\nquery = \"SELECT * FROM users WHERE id = %s\"\ncursor.execute(query, (user_id,))"
                }
            }
        }

    def scan_directories(self, target_url):
        common_paths = ['/admin', '/.env', '/.git', '/config.php', '/phpmyadmin', '/backup', '/wp-admin', '/api/v1']
        found_paths = []
        for path in common_paths:
            try:
                url = f"{target_url.rstrip('/')}{path}"
                res = requests.head(url, timeout=2, allow_redirects=True)
                if res.status_code in [200, 301, 302, 403]:
                    found_paths.append({"path": path, "status": res.status_code})
            except:
                continue
        return found_paths

    def scan_ports(self, host, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080, 8443]
        
        open_ports = []
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        return open_ports

    def perform_scan(self, target_url):
        results = {
            "target": target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "summary": "",
            "severity": "Low",
            "open_ports": [],
            "tech_stack": [],
            "discovered_paths": []
        }

        if not target_url.startswith('http'):
            target_url = f'http://{target_url}'
        
        domain = target_url.split('//')[-1].split('/')[0].split(':')[0]
        results['open_ports'] = self.scan_ports(domain)
        results['discovered_paths'] = self.scan_directories(target_url)

        try:
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            # Security Headers Check
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options',
                'Content-Security-Policy': 'Missing Content-Security-Policy (CSP)',
                'Strict-Transport-Security': 'Missing Strict-Transport-Security',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options'
            }

            for header, vuln_name in security_headers.items():
                if header not in headers:
                    kb_entry = self.knowledge_base.get(vuln_name)
                    results['vulnerabilities'].append({
                        "title": vuln_name,
                        "description": kb_entry['summary'],
                        "severity": kb_entry['severity'],
                        "remediation": kb_entry['remediation'],
                        "exploitation": kb_entry['exploitation'],
                        "owasp": kb_entry.get('owasp', 'N/A'),
                        "patches": kb_entry.get('patches', {})
                    })

            # Tech Stack
            if 'Server' in headers:
                results['tech_stack'].append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                results['tech_stack'].append(f"Powered By: {headers['X-Powered-By']}")

            # Content Analysis
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                kb_entry = self.knowledge_base.get("Exposed HTML Forms")
                results['vulnerabilities'].append({
                    "title": f"Detected {len(forms)} HTML Forms",
                    "description": kb_entry['summary'],
                    "severity": kb_entry['severity'],
                    "remediation": kb_entry['remediation'],
                    "exploitation": kb_entry['exploitation'],
                    "owasp": kb_entry.get('owasp', 'N/A'),
                    "patches": kb_entry.get('patches', {})
                })

            # Heuristic Intelligence Engine
            self._run_heuristic_analysis(results)

        except Exception as e:
            results['summary'] = f"Scan error: {str(e)}"
            results['severity'] = "N/A"
        
        return results

    def _run_heuristic_analysis(self, results):
        """
        Performs heuristic analysis using the internal knowledge base and findings.
        """
        vuln_count = len(results['vulnerabilities'])
        
        # Determine Overall Severity
        severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        max_severity_val = 0
        current_severity = "Low"
        
        for v in results['vulnerabilities']:
            val = severity_map.get(v['severity'], 0)
            if val > max_severity_val:
                max_severity_val = val
                current_severity = v['severity']
        
        results['severity'] = current_severity

        # Generate Analytical Summary
        if vuln_count == 0:
            results['summary'] = (
                f"Security analysis of {results['target']} completed. No immediate "
                "critical vulnerabilities were detected in the surface-level scan."
            )
        else:
            ports_msg = f" Ports {results['open_ports']} are open, increasing the attack surface." if results['open_ports'] else ""
            results['summary'] = (
                f"Analysis complete. {vuln_count} security issues identified. "
                f"Overall risk rating: {current_severity}.{ports_msg}"
            )

        # Intelligence Insight: Correlate findings
        if 80 in results['open_ports'] and "Missing Strict-Transport-Security" in [v['title'] for v in results['vulnerabilities']]:
            results['vulnerabilities'].append({
                "title": "Insight: Potential Man-in-the-Middle Risk",
                "description": "The combination of an open HTTP port (80) and missing HSTS allows for SSL stripping attacks.",
                "severity": "High",
                "remediation": "Force all traffic to HTTPS and enable HSTS immediately.",
                "exploitation": "Use arpspoof to redirect traffic and dns2proxy with sslstrip to intercept and downgrade HTTPS connections to HTTP.",
                "owasp": "A05:2021-Security Misconfiguration",
                "patches": {
                    "nginx": "server {\n    listen 80;\n    return 301 https://$host$request_uri;\n}",
                    "apache": "Redirect permanent / https://yourdomain.com/"
                }
            })
