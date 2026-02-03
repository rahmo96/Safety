import os
import random
from datetime import datetime, timedelta

def generate_auth_logs( count=1000):
    log_dir = os.path.join("..", "logs")
    log_file_path = os.path.join(log_dir,"auth.log")
    hostname = "rahmo-VMware-Platform"
    attack_ip = "141.11.22.33"
    
    with open(log_file_path, "w", encoding="utf-8") as f:
        start_time = datetime.now() - timedelta(minutes=count)
        for i in range(count):
            ts = (start_time + timedelta(seconds=i*2)).strftime("%b %d %H:%M:%S").replace(" 0", "  ")
            # יצירת רצף של כשלונות בסוף הקובץ להפעלת ה-Detector
            is_attack = i > 980 
            user = "admin" if is_attack else "rahmo"
            ip = attack_ip if is_attack else f"192.168.1.{random.randint(10, 20)}"
            
            if is_attack:
                msg = f"sshd[{random.randint(1000, 9000)}]: Failed password for {user} from {ip} port 54322 ssh2"
            else:
                msg = f"sshd[{random.randint(1000, 9000)}]: Accepted password for {user} from {ip} port 22 ssh2"
            
            f.write(f"{ts} {hostname} {msg}\n")
    print(f"Generated 1,000 lines in {log_file_path}")

if __name__ == "__main__":
    generate_auth_logs()