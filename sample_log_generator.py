import random
from datetime import datetime, timedelta

users = ["admin_user", "guest_account", "service_account", "backup_user", "sys_admin"]
ips = ["192.168.1.10", "192.168.1.25", "192.168.1.50", "10.0.0.12", "172.16.0.5"]
files = ["payroll_2023.csv", "customers.db", "config.yaml", "secrets.env", "backup.tar.gz"]
rules = [101, 205, 305, 405, 502]
actions = ["login success", "login failure"]
start_time = datetime(2023, 10, 27, 0, 0, 0)

def random_log_line(timestamp):
    event_type = random.choice(["login", "firewall", "file_access"])

    if event_type == "login":
        return f"{timestamp} {random.choice(users)} {random.choice(actions)} from IP {random.choice(ips)}"

    elif event_type == "firewall":
        return (
            f"{timestamp} firewall_alert: Rule {random.choice(rules)} "
            f"(Deny All) modified by {random.choice(users)} to Allow 0.0.0.0/0"
        )

    else:
        return (
            f"{timestamp} sensitive_file_access: '{random.choice(files)}' "
            f"accessed by {random.choice(users)}"
        )

with open("system_logs.txt", "w") as f:
    current_time = start_time
    for _ in range(10000):
        f.write(random_log_line(current_time.strftime("%Y-%m-%d %H:%M:%S")) + "\n")
        current_time += timedelta(seconds=random.randint(5, 120))

print("system_logs.txt created with 10,000 log entries.")
