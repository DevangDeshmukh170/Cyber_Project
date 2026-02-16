import psutil
import time
from datetime import datetime

# ---------------- CONFIGURATION ----------------
suspicious_keywords = ["keylog", "logger", "hook", "keyboard", "capture"]
suspicious_paths = ["AppData", "Temp", "Downloads"]
log_file = "monitor_log.txt"

known_pids = set()

print("=== Advanced Endpoint Monitoring Tool Started ===\n")

# ---------------- BASELINE SNAPSHOT ----------------
for process in psutil.process_iter(['pid']):
    known_pids.add(process.info['pid'])

# ---------------- CONTINUOUS MONITORING ----------------
while True:
    print(f"\n[SCAN TIME]: {datetime.now()}")
    current_pids = set()

    # -------- PROCESS MONITORING --------
    for process in psutil.process_iter(
        ['pid', 'name', 'cpu_percent', 'memory_info', 'exe']
    ):
        try:
            pid = process.info['pid']
            name = process.info['name']
            exe_path = process.info['exe']
            cpu = process.cpu_percent(interval=0.1)
            memory = process.info['memory_info'].rss / (1024 * 1024)

            current_pids.add(pid)

            # -------- NEW PROCESS DETECTION --------
            if pid not in known_pids:
                print(f"[NEW PROCESS] {name} (PID: {pid})")
                print(f"   CPU Usage: {cpu}%")
                print(f"   Memory Usage: {memory:.2f} MB")
                print("-" * 50)

            # -------- SUSPICIOUS NAME DETECTION --------
            for keyword in suspicious_keywords:
                if keyword in name.lower():
                    alert_message = (
                        f"\n[SUSPICIOUS PROCESS NAME DETECTED]\n"
                        f"Process: {name}\n"
                        f"PID: {pid}\n"
                        f"Path: {exe_path}\n"
                        f"CPU: {cpu}%\n"
                        f"Memory: {memory:.2f} MB\n"
                        f"Time: {datetime.now()}\n"
                        f"{'-'*60}\n"
                    )

                    print(alert_message)

                    with open(log_file, "a", encoding="utf-8") as file:
                        file.write(alert_message)

            # -------- SUSPICIOUS PATH DETECTION --------
            if exe_path:
                for folder in suspicious_paths:
                    if folder.lower() in exe_path.lower():
                        alert_message = (
                            f"\n[SUSPICIOUS EXECUTION PATH DETECTED]\n"
                            f"Process: {name}\n"
                            f"PID: {pid}\n"
                            f"Path: {exe_path}\n"
                            f"CPU: {cpu}%\n"
                            f"Memory: {memory:.2f} MB\n"
                            f"Time: {datetime.now()}\n"
                            f"{'-'*60}\n"
                        )

                        print(alert_message)

                        with open(log_file, "a", encoding="utf-8") as file:
                            file.write(alert_message)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    known_pids = current_pids

    # -------- NETWORK MONITORING --------
    print("\nActive Network Connections:")

    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status == "ESTABLISHED" and conn.raddr:
                pid = conn.pid
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                print(f"PID {pid} -> Connected to {remote_ip}:{remote_port}")

        except:
            pass

    time.sleep(5)