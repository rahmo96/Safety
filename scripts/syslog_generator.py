import os
import random
from datetime import datetime, timedelta

def generate_syslog( count=1000):
    log_dir = os.path.join("..", "logs")
    log_file_path = os.path.join(log_dir,"syslog.log")
    hostname = "rahmo-VMware-Platform"
    services = ["cron", "kernel", "dhclient", "systemd", "dbus-daemon"]
    
    with open(log_file_path, "w", encoding="utf-8") as f:
        start_time = datetime.now() - timedelta(minutes=count)
        for i in range(count):
            ts = (start_time + timedelta(seconds=i)).strftime("%b %d %H:%M:%S").replace(" 0", "  ")
            service = random.choice(services)
            pid = random.randint(100, 9999)
            msg = f"Message number {i} from service {service}"
            f.write(f"{ts} {hostname} {service}[{pid}]: {msg}\n")
    print(f"Generated 1,000 lines in {log_file_path}")

if __name__ == "__main__":
    generate_syslog()