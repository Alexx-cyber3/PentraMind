 PentraMnd is a comprehensive security scanning and vulnerability management platform designed for both traditional web
  applications and modern AI-driven systems. It provides a dual-interface for Red Team (offensive security/discovery) and
  Blue Team (defensive security/remediation) operations.

  Key Capabilities

   1. Traditional Web Security Scanner (scanner.py):
       * Heuristic Analysis: Automatically checks for common web misconfigurations, such as missing critical security
         headers (Content-Security-Policy, X-Frame-Options, HSTS, etc.).
       * OWASP Mapping: Vulnerabilities are mapped directly to the OWASP Top 10 (e.g., A03:2021-Injection,
         A05:2021-Security Misconfiguration).
       * Remediation Guidance: Provides specific patches for popular web servers like Nginx and Apache to fix discovered
         issues.

   2. AI/LLM Security Scanner (ai_scanner.py):
       * Jailbreak Testing: Specialized module that tests AI bots for Prompt Injection (LLM01) using various bypass
         techniques like "Developer Mode Bypass" and "Roleplay Attacks."
       * Automated Evaluation: Uses an LLM (via OpenAI) to analyze the responses from a target AI and determine if
         sensitive information was leaked or safety guardrails were bypassed.

   3. Red & Blue Team Workflows:
       * Red Team Dashboard: Allows users to add targets and trigger scans (Traditional or AI-based).
       * Blue Team Dashboard: Focused on reports, impact analysis, and remediation steps to help security teams harden
         their infrastructure.


      add openai key to work
      

✦ PentraMnd: Architectural & Functional Analysis

  PentraMnd is an automated, AI-powered security assessment (penetration testing) platform built with a Flask backend
  and a futuristic dual-perspective frontend interface (Red Team vs. Blue Team).

  ---

  🛠️ Key Architectural Components

  1. Central Coordinator & Web Interface (app.py, models.py, forms.py)
   * app.py: The main entry point of the application. It manages routing, user authentication (via Flask-Login), and
     invokes the scanning engines.
   * models.py: Implements the SQLite database schema with Flask-SQLAlchemy.
       * User: Handles user registration, sessions, and hashes password credentials safely.
       * Target: Represents target systems (URLs, IP addresses, or specialized AI Bot endpoints) under test.
       * ScanReport: Persists complete scan results, vulnerability logs, and classification categories.
   * forms.py: Integrates Flask-WTF and wtforms for validated user inputs (e.g., login, registration, and new scan
     requests).

  2. Traditional Security Scanner (scanner.py)
  This is a comprehensive heuristic/DAST (Dynamic Application Security Testing) engine:
   * OSINT & Reconnaissance: Performs subdomain enumeration, DNS resolution (dnspython), WHOIS lookups (python-whois),
     and basic TCP port scanning.
   * Vulnerability Detection (DAST): Analyzes HTTP security headers (e.g., X-Frame-Options, Content-Security-Policy),
     and probes endpoints for common vulnerabilities like SQL Injection (SQLi), Cross-Site Scripting (XSS), and CSRF.
   * Knowledge Base: Connects detected issues to remediation instructions, offering actionable "Patch-as-Code"
     configurations (for Nginx, Apache, or Python).

  3. AI Safety & Prompt Injection Scanner (ai_scanner.py)
  A specialized scanning module targeting Large Language Model (LLM) applications:
   * OWASP Top 10 for LLMs: Focuses on prompt injection (LLM01) and jailbreaking vectors.
   * Attack Simulation: Uses a suite of standard jailbreak payloads to test the AI system's boundary controls.
   * Evaluation: Integrates with the OpenAI API to parse and analyze responses, determining whether the prompt injection
     attempt was successful, partially mitigated, or fully blocked.

  4. Dual-Perspective User Interface (templates/)
  The frontend uses Flask Jinja2 templates styled with a dark, modern visual theme.
   * Red Team Mode (Offensive): Focuses on exploitable vectors, severity ratings, and target weakness visualization
     (templates/red_team.html).
   * Blue Team Mode (Defensive): Focuses on hardening, risk mitigation, and specific patch-as-code snippets mapped from
     the scanner's knowledge base (templates/blue_team.html).
   * Dashboard & Reports: Standardize scan execution controls (new_scan.html) and historical overview (dashboard.html).

  ---

  🔄 End-to-End Operational Flow

   1. Authentication & Target Setup: The user signs up, logs in, and adds a Target configuration, selecting whether it
      is a traditional web service or an AI bot.
   2. Scan Execution:
       * Traditional Web target: app.py invokes SecurityScanner from scanner.py.
       * AI bot target: app.py invokes AIScanner from ai_scanner.py.
   3. Data Persistence: Scan findings are compiled into structured JSON payloads and saved to the SQLite database
      (instance/pentramind.db) under a ScanReport.
   4. Interactive Analysis: The user is navigated to report.html, allowing them to toggle dynamically between the Red
      Team (Offensive) and Blue Team (Defensive) perspectives of the audit.
      
