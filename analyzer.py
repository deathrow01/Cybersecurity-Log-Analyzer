import re
from pathlib import Path


def read_logs(filename):
    """Read and validate log entries from a file."""

    logs = []
    invalid_lines = 0

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                parts = line.split(" ", 3)

                if len(parts) != 4:
                    invalid_lines += 1
                    continue

                date, time, level, message = parts

                if level not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
                    invalid_lines += 1
                    continue

                logs.append({
                    "date": date,
                    "time": time,
                    "level": level,
                    "message": message
                })

    except FileNotFoundError:
        print("Error: Log file not found:", filename)
        return None, 0

    return logs, invalid_lines


def analyze_logs(logs):
    """Analyze log levels and detect possible security events."""

    levels = {
        "DEBUG": 0,
        "INFO": 0,
        "WARNING": 0,
        "ERROR": 0
    }

    failed_by_ip = {}
    suspicious_ips = set()
    security_events = []

    keywords = [
        "failed login",
        "suspicious activity",
        "unusual traffic",
        "security breach"
    ]

    for log in logs:
        level = log["level"]
        message = log["message"]
        message_lower = message.lower()

        levels[level] += 1

        match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            message
        )

        ip = match.group() if match else None

        if "failed login" in message_lower and ip:
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

        if any(keyword in message_lower for keyword in keywords):
            security_events.append(log)

            if ip:
                suspicious_ips.add(ip)

    return levels, failed_by_ip, suspicious_ips, security_events


def display_report(logs, invalid_lines, results):
    """Display the analysis results in the terminal."""

    levels, failed_by_ip, suspicious_ips, security_events = results

    print("\n===== SERVER LOG REPORT =====")
    print("Valid log entries:", len(logs))
    print("Invalid log entries:", invalid_lines)

    for level, count in levels.items():
        print(level + ":", count)

    print("\n===== FAILED LOGINS BY IP =====")

    if failed_by_ip:
        for ip, count in failed_by_ip.items():
            print(ip, ":", count, "failed login(s)")

            if count >= 3:
                print("ALERT: Repeated failed logins from", ip)
    else:
        print("No failed logins linked to an IP address.")

    print("\n===== SUSPICIOUS IP ADDRESSES =====")

    if suspicious_ips:
        for ip in sorted(suspicious_ips):
            print(ip)
    else:
        print("No suspicious IP addresses found.")

    print("\n===== SECURITY EVENTS =====")

    for log in security_events:
        print(
            log["date"],
            log["time"],
            log["level"],
            log["message"]
        )


def save_report(filename, logs, invalid_lines, results):
    """Save the analysis results to a text report."""

    levels, failed_by_ip, suspicious_ips, security_events = results

    report_file = Path(__file__).parent / "security_report.txt"

    with open(report_file, "w", encoding="utf-8") as file:

        file.write("===== CYBERSECURITY LOG REPORT =====\n")
        file.write(f"Valid log entries: {len(logs)}\n")
        file.write(f"Invalid log entries: {invalid_lines}\n\n")

        file.write("===== LOG LEVEL SUMMARY =====\n")

        for level, count in levels.items():
            file.write(f"{level}: {count}\n")

        file.write("\n===== FAILED LOGINS BY IP =====\n")

        if failed_by_ip:
            for ip, count in failed_by_ip.items():
                file.write(f"{ip}: {count} failed login(s)\n")

                if count >= 3:
                    file.write(
                        f"ALERT: Repeated failed logins from {ip}\n"
                    )
        else:
            file.write("No failed logins linked to an IP address.\n")

        file.write("\n===== SUSPICIOUS IP ADDRESSES =====\n")

        for ip in sorted(suspicious_ips):
            file.write(f"{ip}\n")

        file.write("\n===== SECURITY EVENTS =====\n")

        for log in security_events:
            file.write(
                f"{log['date']} {log['time']} "
                f"{log['level']} {log['message']}\n"
            )

    print("\nReport saved to:", report_file)


def main():
    """Main function of the program."""

    filename = Path(__file__).parent / "server_logs.txt"

    logs, invalid_lines = read_logs(filename)

    if logs is None:
        return

    results = analyze_logs(logs)

    display_report(logs, invalid_lines, results)

    save_report(filename, logs, invalid_lines, results)


if __name__ == "__main__":
    main()