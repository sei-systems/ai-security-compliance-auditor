import google.generativeai as genai

# 1. Configuration
genai.configure(api_key="YOUR_API_KEY")

def run_audit():
    # READ FROM FILE
    try:
        with open('system_logs.txt', 'r') as file:
            log_data = file.read()
    except FileNotFoundError:
        print("Error: system_logs.txt not found.")
        return

    print("--- ANALYSIS IN PROGRESS (GEMINI 2.0 FLASH) ---")
    
    try:
        # Using the version you found works!
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        prompt = f"""
        ACT AS: Senior SOC2 Auditor.
        TASK: Analyze the provided logs for security breaches, NIST violations, or suspicious patterns.
        OUTPUT: Provide a 'Security Audit Summary' in Markdown format with headers for HIGH, MEDIUM, and LOW risks.
        
        LOG DATA:
        {log_data}
        """
        
        response = model.generate_content(prompt)
        
        # SAVE TO A REPORT FILE
        with open('Audit_Report.md', 'w') as f:
            f.write(response.text)
            
        print("\n--- SUCCESS: Report generated as 'Audit_Report.md' ---")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    run_audit()