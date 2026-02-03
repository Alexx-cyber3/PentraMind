import socket
import requests
import time
import re
from bs4 import BeautifulSoup

class AIScanner:
    def __init__(self, api_key=None):
        # API key no longer required for the local free version
        self.knowledge_base = {
            "Missing Content-Security-Policy (CSP)": {
                "summary": "The application lacks a Content-Security-Policy, which is a critical defense against Cross-Site Scripting (XSS) and injection attacks.",
                "remediation": "Implement a 'Content-Security-Policy' header. Start with 'default-src self' and gradually allow necessary external resources.",
                "severity": "High"
            },
            "Missing X-Frame-Options": {
                "summary": "Without X-Frame-Options, your site can be embedded in an iframe on a malicious domain, leading to Clickjacking attacks.",
                "remediation": "Add 'X-Frame-Options: SAMEORIGIN' or 'DENY' to your server's HTTP response headers.",
                "severity": "Medium"
            },
            "Missing Strict-Transport-Security": {
                "summary": "HSTS is not enabled, meaning the browser might attempt to connect via insecure HTTP before redirecting to HTTPS.",
                "remediation": "Enable HSTS by adding the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                "severity": "Medium"
            },
            "Missing X-Content-Type-Options": {
                "summary": "The lack of 'nosniff' directive allows browsers to guess MIME types, which can lead to script injection via uploaded files.",
                "remediation": "Add the 'X-Content-Type-Options: nosniff' header to all responses.",
                "severity": "Low"
            },
            "Exposed HTML Forms": {
                "summary": "Detected interactive input fields. These are potential entry points for SQL Injection, XSS, and CSRF if not properly protected.",
                "remediation": "Ensure all form inputs use server-side validation, prepared statements for DB queries, and CSRF tokens.",
                "severity": "Info"
            }
        }

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
            "tech_stack": []
        }

        if not target_url.startswith('http'):
            target_url = f'http://{target_url}'
        
        domain = target_url.split('//')[-1].split('/')[0].split(':')[0]
        results['open_ports'] = self.scan_ports(domain)

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
                        "remediation": kb_entry['remediation']
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
                    "remediation": kb_entry['remediation']
                })

            # Local AI Analysis Engine
            self.run_local_analysis(results)

        except Exception as e:
            results['summary'] = f"Scan error: {str(e)}"
            results['severity'] = "N/A"
        
        return results

    def run_local_analysis(self, results):
        """
        Simulates AI reasoning using the internal knowledge base and findings.
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

        # Generate "Intelligent" Summary
        if vuln_count == 0:
            results['summary'] = (
                f"PENTRAMIND AI analysis of {results['target']} completed. No immediate "
                "critical vulnerabilities were detected in the surface-level scan. "
                "The target appears to have basic security hardening in place."
            )
        else:
            ports_msg = f" Ports {results['open_ports']} are open, which increases the attack surface." if results['open_ports'] else ""
            results['summary'] = (
                f"Analysis complete. PENTRAMIND AI identified {vuln_count} security issues. "
                f"The most significant risk is rated as {current_severity}.{ports_msg} "
                "Immediate remediation of high-severity findings is recommended to prevent unauthorized access."
            )

        # Add an "AI Insight" based on combinations
        if 80 in results['open_ports'] and "Missing Strict-Transport-Security" in [v['title'] for v in results['vulnerabilities']]:
            results['vulnerabilities'].append({
                "title": "AI Insight: Man-in-the-Middle Risk",
                "description": "The combination of an open HTTP port (80) and missing HSTS allows for SSL stripping attacks.",
                "severity": "High",
                "remediation": "Force all traffic to HTTPS and enable HSTS immediately."
            })
