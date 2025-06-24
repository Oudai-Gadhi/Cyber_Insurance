from .utils import run_cmd
import re

def run_check(report, config):
    report.write("\n[GUEST/ANONYMOUS ACCOUNTS]\n")
    penalty = 0
    try:
        with open('/etc/passwd') as f:
            for line in f:
                if re.match(r'^(guest|anonymous):', line):
                    report.write(f"Guest/anonymous account found: {line.split(':')[0]}\n")
                    penalty += 10
    except Exception:
        pass
    if penalty == 0:
        report.write("No guest or anonymous accounts found.\n")
    return penalty
