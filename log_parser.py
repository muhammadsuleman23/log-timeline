import json
import subprocess
from collections import Counter
from datetime import datetime

CRASH_WORDS = (
    "segfault", "core dumped", "dumped core", "out of memory",
    "oom-kill", "killed process", "kernel panic",
)
SERVICE_FAIL_WORDS = ("failed with result",)
FAILED_LOGIN_WORDS = (
    "failed password", "authentication failure",
    "incorrect password", "invalid user",
)
LOGIN_WORDS = ("session opened for user", "accepted password", "accepted publickey")
LOGOUT_WORDS = ("session closed for user",)
ADMIN_SOURCES = ("sudo", "pkexec", "su")


def classify(message, priority, source):
    """Ek log line ko category do. None matlab ignore."""
    m = message.lower()
    # Normal background noise ko ignore karo
    if source == "CRON" and ("session opened" in m or "session closed" in m):
        return None
    if "auth could not identify password" in m or "conversation failed" in m:
        return None
    if any(w in m for w in FAILED_LOGIN_WORDS):
        return "failed_login"
    if any(w in m for w in CRASH_WORDS):
        return "crash"
    if any(w in m for w in SERVICE_FAIL_WORDS):
        return "service_failed"
    if any(w in m for w in LOGIN_WORDS):
        return "sudo" if source in ADMIN_SOURCES else "login"
    if any(w in m for w in LOGOUT_WORDS):
        return None if source in ADMIN_SOURCES else "logout"
    if priority <= 3:
        return "error"
    if priority == 4:
        return "warning"
    return None


def clean_message(raw):
    if isinstance(raw, list):
        return bytes(raw).decode("utf-8", errors="replace")
    return str(raw or "")


def get_events(since="24 hours ago"):
    result = subprocess.run(
        ["journalctl", "-o", "json", "--no-pager", "--since", since],
        capture_output=True, text=True, errors="replace",
    )
    events = []
    last_boot = None

    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
        when = datetime.fromtimestamp(ts).isoformat(timespec="seconds")
        message = clean_message(entry.get("MESSAGE"))
        source = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "unknown"

        # Naya boot tab maano jab boot id badle aur boot ko 60 second se kam hue hon
        boot_id = entry.get("_BOOT_ID")
        if boot_id and boot_id != last_boot:
            uptime_us = int(entry.get("__MONOTONIC_TIMESTAMP", "0"))
            if uptime_us < 60_000_000:
                events.append({
                    "time": when, "type": "boot",
                    "source": "system", "message": "System boot",
                })
            last_boot = boot_id

        kind = classify(message, int(entry.get("PRIORITY", 6)), source)
        if kind:
            events.append({
                "time": when, "type": kind,
                "source": source, "message": message[:200],
            })
    return events


if __name__ == "__main__":
    events = get_events()
    print(f"Total events: {len(events)}\n")
    for kind, count in Counter(e["type"] for e in events).most_common():
        print(f"  {kind:<16} {count}")
