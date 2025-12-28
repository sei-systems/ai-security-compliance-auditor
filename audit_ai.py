import google.generativeai as genai
import re
import os
from datetime import datetime

# ==========================================
# 1. AUDITOR CONFIGURATION (SYSTEM BRAIN)
# ==========================================
SYSTEM_INSTRUCTION = """
You are a Senior SOC2 and NIST 800-53 Auditor. 
Your goal is to analyze raw security logs and provide an Audit Readiness Report.

CORE REQUIREMENTS:
1. Always map events to specific Control IDs:
   - SOC2 CC6.1 (Access Protection)
   - SOC2 CC7.2 (Incident Monitoring)
   - NIST AC-2 (Account Management)
   - NIST AU-6 (Audit Review)
2. Use a structured Markdown format.
3. Every report MUST have distinct headers for HIGH, MEDIUM, and LOW risks.
4. Provide a "Remediation" column for any identified risks.

OUTPUT RULES:
1. Every section (Summary, High, Medium, Low) MUST be a Markdown table.
2. Use exactly these headers for every table: 
   | ID | Event | Control Mapping | Severity | Remediation |
3. Do not use nested bullets inside table cells; use semicolon-separated sentences.
4. If a severity level has no logs, the table should contain one row: | N/A | No issues found | N/A | N/A | N/A |
"""

# Configure API Key
api_key = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=api_key)

# Initialize the model with baked-in instructions
model = genai.GenerativeModel(
    model_name='gemini-2.5-flash',
    system_instruction=SYSTEM_INSTRUCTION
)

# ==========================================
# 2. THE TRIAGE LAYER (PRE-PROCESSING)
# ==========================================
def preprocess_logs(raw_data):
    """
    Filters for high-value events and masks sensitive data.
    This reduces token costs and ensures privacy compliance.
    """
    lines = raw_data.splitlines()
    filtered_lines = []
    
    # Audit-relevant keywords to keep
    keywords = ["FAIL", "DENIED", "ERROR", "CRITICAL", "UNAUTHORIZED", "SUDO", "LOGIN", "LOCKOUT"]
    
    for line in lines:
        if any(key in line.upper() for key in keywords):
            # MASKING: Redact passwords/tokens for SOC2 Privacy requirements
            clean_line = re.sub(r'(password|passwd|token|key)=\S+', r'\1=[REDACTED]', line, flags=re.IGNORECASE)
            filtered_lines.append(clean_line)
            
    return "\n".join(filtered_lines)

# ==========================================
# 3. MAIN AUDIT EXECUTION
# ==========================================
def run_audit():
    input_file = 'system_logs.txt'
    
    # --- STEP 1: INGESTION ---
    try:
        with open(input_file, 'r') as file:
            raw_log_data = file.read()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    # --- STEP 2: TRIAGE ---
    processed_logs = preprocess_logs(raw_log_data)
    
    if not processed_logs:
        print("No audit-relevant events found. Skipping API call to save costs.")
        return

    print(f"--- ANALYZING {len(processed_logs.splitlines())} RELEVANT EVENTS ---")
    
    try:
        # --- STEP 3: ANALYSIS ---
        # The instructions are already in the 'model' object via system_instruction
        prompt = f"Analyze the following logs for the daily compliance check:\n\n{processed_logs}"
        
        response = model.generate_content(prompt)
        
        # --- STEP 4: PERSISTENCE (AUDIT TRAIL) ---
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        report_name = f"Audit_Report_{timestamp}.md"
        
        with open(report_name, 'w') as f:
            f.write(response.text)
            
        print(f"\n--- SUCCESS: Report generated as '{report_name}' ---")
        
    except Exception as e:
        print(f"\n[!] Error during API analysis: {e}")

if __name__ == "__main__":
    run_audit()