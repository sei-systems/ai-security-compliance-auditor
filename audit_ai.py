import google.generativeai as genai
import re
import os
from datetime import datetime

# ==========================================
# 1. AUDITOR CONFIGURATION (SYSTEM BRAIN)
# ==========================================
SYSTEM_INSTRUCTION = """
You are a Senior SOC2 and NIST 800-53 Auditor. 
TASK: Map logs to the MOST RELEVANT controls from the following audit library:

--- AUDIT LIBRARY ---
- ACCESS CONTROL: SOC2 CC6.1, NIST AC-2 (Account Mgmt), NIST AC-3 (Least Privilege)
- AUDIT & ACCOUNTABILITY: SOC2 CC7.2, NIST AU-6 (Audit Review), NIST AU-12 (Audit Generation)
- IDENTIFICATION/AUTH: SOC2 CC6.3, NIST IA-2 (MFA/Identification)
- SYSTEM INTEGRITY: SOC2 CC7.1, NIST SI-4 (Information System Monitoring)
- INCIDENT RESPONSE: SOC2 CC7.3, NIST IR-4 (Incident Handling)

OUTPUT FORMAT RULES:
1. Use the LIST format ONLY. No tables.
2. Follow this exact template for every finding:

Control ID: [ID]
Event: [Title]
Details: [Analysis]
Remediation: [Fix]

(Ensure there is exactly one empty line between findings)

EXAMPLE:
Control ID: SOC2 CC6.1 / NIST AC-2
Event: Unauthorized sudo attempt
Details: User 'webapp' tried to access /etc/shadow.
Remediation: Remove sudo privileges for service accounts.
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