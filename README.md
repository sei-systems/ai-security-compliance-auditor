AI Security Auditor: SOC2 & NIST Log Analysis

This project is an automated security log analysis tool powered by Gemini. It is designed to bridge the gap between raw system logs and formal compliance documentation (SOC2 and NIST 800-53). It filters high-volume system logs for security-relevant events, analyzes them using a "baked-in" auditor's brain, and generates a structured, risk-prioritized audit report.

Key Features
Continuous Compliance Mapping: Automatically maps detected events to specific controls such as NIST AC-2 (Account Management) and SOC2 CC6.1 (Logical Access).
Intelligent Triage: Pre-processes logs to remove noise (health checks, successful cron jobs) while identifying critical threats like brute-force attempts and privilege escalation.
Privacy-First Analysis: Automatically redacts sensitive fields like passwords, tokens, and keys before sending data to the AI for analysis.
Auditor-Ready Reports: Generates structured Markdown reports including an Executive Summary, Findings Summary, and a Detailed List of findings with remediation steps.

Tech Stack
Language: Python 3.9+
Core AI: Google Gemini 2.5 Flash 
Security Frameworks: SOC2 Trust Services Criteria, NIST 800-53

Installation
Clone the repository: 'git clone https://github.com/yourusername/ai-security-auditor.git'
Change to new directory: 'cd ai-security-auditor'
Install dependencies: 'pip install google-generativeai'
Set up your API Key:Export your Gemini API key to your environment: 'export GEMINI_API_KEY='your_actual_key_here''

Usage
Prepare your logs: Place your raw system logs into a file named system_logs.txt.
Run the audit: 'python audit_ai.py'
Review the results: A new report will be generated in the root directory with a timestamp (e.g., Audit_Report_2025-12-28_16-45.md).

Audit Library Coverage
The AI is configured to monitor and report against the following specific control domains:
Domain                  | SOC2 Control  | NIST 800-53
Access Control          | CC6.1         | AC-2, AC-3
Audit & Accountability  | CC7.2         | AU-6, AU-12
Identification & Auth   | CC6.3         | IA-2
System Integrity        | CC7.1         | SI-4
Incident Response       | CC7.3         | IR-4

Project Structure
audit_ai.py: The main auditor script containing the Triage Layer and AI Integration.
system_logs.txt: Your raw log data source (Input).
Audit_Report_YYYY-MM-DD.md: The generated compliance report (Output).