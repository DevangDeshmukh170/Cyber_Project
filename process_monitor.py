import psutil
import time
from datetime import datetime

suspicious_keywords = ["keylog", "logger", "hook", "keyboard", "capture"]
known_pids = set()
log_file = "monitor_log.txt"

print("🚀 Advanced Behavioral Process Monitor Started...\n")

# Initial snapshot of running processes
for process in psutil.process_iter(['pid']):
    known_pids.add(process.info['pid'])

while True:
    print(f"\n[SCAN TIME]: {datetime.now()}")

    current_pids = set()

    for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            pid = process.info['pid']
            name = process.info['name']
            cpu = process.cpu_percent(interval=0.1)
            memory = process.info['memory_info'].rss / (1024 * 1024)  # Convert to MB

            current_pids.add(pid)

            # Detect new process
            if pid not in known_pids:
                print(f"[NEW PROCESS DETECTED] {name} (PID: {pid})")

            # Check suspicious keywords
            for keyword in suspicious_keywords:
                if keyword in name.lower():

                    alert_message = (
                        f"\n[⚠ ALERT] Suspicious Process Detected!\n"
                        f"Process Name: {name}\n"
                        f"PID: {pid}\n"
                        f"CPU Usage: {cpu}%\n"
                        f"Memory Usage: {memory:.2f} MB\n"
                        f"Detected At: {datetime.now()}\n"
                        f"{'-'*60}\n"
                    )

                    print(alert_message)

                    with open(log_file, "a") as file:
                        file.write(alert_message)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    known_pids = current_pids
    time.sleep(5)