import os
import random
import time
from datetime import datetime, timedelta

def generate_access_logs( count=1000):
    log_dir = os.path.join("..", "logs")
    log_file_path = os.path.join(log_dir,"access.log")
    print(log_file_path)
    ips = [f"192.168.1.{i}" for i in range(1, 100)] + [f"10.0.0.{i}" for i in range(1, 20)]
    attack_ips = ["141.11.22.33", "185.92.11.22", "45.155.205.233"]
    
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
    
    normal_paths = ["/", "/home", "/products", "/contact", "/search?q=security", "/api/v1/status", "/assets/style.css", "/js/main.js"]
    suspicious_paths = ["/admin", "/wp-login.php", "/.env", "/config.php", "/etc/passwd", "/phpmyadmin", "/.git/config"]
    
    statuses = [200, 200, 200, 200, 301, 302, 404, 404, 500]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)",
        "curl/7.68.0",
        "sqlmap/1.4.11#stable (http://sqlmap.org)", 
        "Nmap Scripting Engine; https://nmap.org/book/nse.html" 
    ]

    print(f"Generating {count} unique log lines...")
    
    with open(log_file_path, "w", encoding="utf-8") as f:
        current_time = datetime.now() - timedelta(hours=1)
        
        for i in range(count):
            current_time += timedelta(milliseconds=random.randint(100, 2000))
            timestamp = current_time.strftime("%d/%b/%Y:%H:%M:%S +0200")
            
            is_attack = random.random() < 0.15
            
            if is_attack:
                ip = random.choice(attack_ips)
                path = random.choice(suspicious_paths) if random.random() > 0.5 else "/login"
                status = random.choice([401, 403, 404])
                method = random.choice(["GET", "POST"])
            else:
                ip = random.choice(ips)
                path = random.choice(normal_paths)
                status = random.choice(statuses)
                method = random.choice(methods)

            size = random.randint(200, 15000)
            agent = random.choice(agents)
            
            log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"\n'
            f.write(log_line)

    print(f"Successfully saved to {log_file_path}")

if __name__ == "__main__":
    generate_access_logs()