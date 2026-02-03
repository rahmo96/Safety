import os
import random
from datetime import datetime, timedelta

def generate_systemd_auth_logs(count=1000):
    log_dir = os.path.join("..", "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_file_path = os.path.join(log_dir, "auth_systemd.log")
    hostname = "rahmo-VMware-Virtual-Platform"
    attack_ip = "141.11.22.33"
    
    with open(log_file_path, "w", encoding="utf-8") as f:
        start_time = datetime.now() - timedelta(minutes=count/10)
        
        for i in range(count):
            current_time = start_time + timedelta(seconds=i * 0.5)
            ts = current_time.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+02:00"
            
            is_attack = i > 950 
            user = "admin" if is_attack else "rahmo"
            ip = attack_ip if is_attack else f"192.168.1.{random.randint(10, 20)}"
            pid = random.randint(1000, 9000)
            
            if is_attack:
                msg = f"sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(30000, 60000)} ssh2"
            else:
                msg = f"sshd[{pid}]: Accepted password for {user} from {ip} port 22 ssh2"
            
            f.write(f"{ts} {hostname} {msg}\n")
            
    print(f"Generated {count} lines in {log_file_path}")
    print(f"Attack simulation: {attack_ip} performed {count - 951} failed attempts.")

if __name__ == "__main__":
    generate_systemd_auth_logs()