import os
import random
from datetime import datetime, timedelta

def generate_vulnerable_syslog(count=1000):
    log_dir = os.path.join("..", "logs")
    if not os.path.exists(log_dir): os.makedirs(log_dir)
    
    log_file_path = os.path.join(log_dir, "syslog.log")
    hostname = "rahmo-VMware-Virtual-Platform"
    attacker_ip = "141.11.22.33"

    with open(log_file_path, "w", encoding="utf-8") as f:
        start_time = datetime.now() - timedelta(minutes=count)
        for i in range(count):
            ts = (start_time + timedelta(seconds=i)).isoformat() + "+02:00"
            
            if 100 < i < 110: # Brute Force
                service, msg = "sshd", f"Failed password for root from {attacker_ip} port 54322 ssh2"
            elif i == 300: # Path Traversal
                service, msg = "apache2", f"GET /etc/passwd HTTP/1.1 from {attacker_ip}"
            elif i == 500: # Suspicious Agent
                service, msg = "nginx", f"Inbound request from 192.168.1.100 - user-agent: 'sqlmap-scanner'"
            elif i == 700: # Privileged Access
                service, msg = "pkexec", "pam_unix(polkit-1:session): session opened for user root by rahmo"
            else:
                service, msg = random.choice(["systemd", "kernel"]), f"General system event {i}"

            f.write(f"{ts} {hostname} {service}: {msg}\n")
    print(f"✅ Created {log_file_path} with Privileged Access event.")

if __name__ == "__main__":
    generate_vulnerable_syslog()