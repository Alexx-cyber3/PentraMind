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
      
