import google.generativeai as genai
import re
import os
from datetime import datetime

# ==========================================
# 1. AUDITOR CONFIGURATION (SYSTEM BRAIN)
# ==========================================
SYSTEM_INSTRUCTION = """
You are a Senior SOC2 and NIST 800-53 Auditor. 
TASK: Map logs to the MOST RELEVANT controls and provide a full Audit Report.

--- REPORT STRUCTURE ---
1.  ### Executive Summary: Provide a high-level 2-3 sentence overview of the security posture found in these logs.
2.  ### Summary of Findings: List the total count of High, Medium, and Low risk events detected.
3.  ### Detailed Findings: (Follow the List Format below for this section).

--- DETAILED LIST FORMAT ---
- Use the LIST format ONLY for this section. No tables.
- Format each finding exactly as follows:

Control ID: [Pick the most relevant IDs from the Library below]
Event: [Title]
Details: [Analysis]
Remediation: [Fix steps]

(New line between findings)

--- AUDIT LIBRARY ---
- ACCESS CONTROL: SOC2 CC6.1, NIST AC-2, NIST AC-3
- AUDIT & ACCOUNTABILITY: SOC2 CC7.2, NIST AU-6, NIST AU-12
- IDENTIFICATION/AUTH: SOC2 CC6.3, NIST IA-2
- SYSTEM INTEGRITY: SOC2 CC7.1, NIST SI-4
- INCIDENT RESPONSE: SOC2 CC7.3, NIST IR-4
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