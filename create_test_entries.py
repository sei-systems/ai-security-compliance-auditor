import random
from datetime import datetime, timedelta

def generate_test_logs(filename="system_logs.txt", count=500):
    ips = ["192.168.1.10", "10.0.0.5", "172.16.254.1", "192.168.1.50"]
    malicious_ips = ["45.33.22.11", "185.220.101.5"]
    users = ["admin", "jdoe", "db_user", "webapp"]
    
    log_templates = [
        "INFO: System health check - CPU {cpu}% Memory {mem}%",
        "INFO: Cron job 'cleanup_tmp' completed successfully.",
        "INFO: User '{user}' logged in from {ip}.",
        "WARN: Low disk space on /var/log (85% full).",
        "ERROR: Failed login attempt for user '{user}' from {ip}.",
        "CRITICAL: Unauthorized sudo attempt by '{user}' on /etc/shadow!",
        "ERROR: Connection timeout from database_cluster_01.",
        "INFO: Outbound connection established to {mal_ip}:443 [Data: {size}MB]"
    ]

    start_time = datetime.now() - timedelta(hours=24)
    
    with open(filename, "w") as f:
        for i in range(count):
            # Advance time slightly for each log entry
            log_time = start_time + timedelta(seconds=i * 172) 
            timestamp = log_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Weighted random choice: 85% Noise, 15% Issues
            if random.random() > 0.15:
                # Routine Logs (Noise)
                msg = random.choice(log_templates[:3]).format(
                    cpu=random.randint(5, 40),
                    mem=random.randint(20, 60),
                    user=random.choice(users),
                    ip=random.choice(ips)
                )
            else:
                # Security Issues (Valid Hits)
                template = random.choice(log_templates[3:])
                msg = template.format(
                    user=random.choice(users + ["root"]),
                    ip=random.choice(malicious_ips + [random.choice(ips)]),
                    mal_ip=random.choice(malicious_ips),
                    size=random.randint(500, 2000)
                )
            
            f.write(f"[{timestamp}] {msg}\n")

if __name__ == "__main__":
    generate_test_logs()
    print("Generated 500 lines of test logs in 'system_logs.txt'")