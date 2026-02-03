import os
import random
from datetime import datetime, timedelta

def generate_systemd_logs( count=1000):
    log_dir = os.path.join("..", "logs")
    log_file_path = os.path.join(log_dir,"systemd.log")
    hostname = "rahmo-VMware-Platform"
    services = ["systemd", "networkd", "dockerd", "resolved"]
    
    with open(log_file_path, "w", encoding="utf-8") as f:
        start_time = datetime.now() - timedelta(minutes=count)
        for i in range(count):
            ts = (start_time + timedelta(seconds=i)).isoformat() + "+02:00"
            service = random.choice(services)
            msg = f"Service unit {service}.service reached target."
            f.write(f"{ts} {hostname} {service}[1]: {msg}\n")
    print(f"Generated 1,000 lines in {log_file_path}")

if __name__ == "__main__":
    generate_systemd_logs()