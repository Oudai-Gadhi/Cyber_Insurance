from .utils import run_cmd

def run_check(report, config):
    report.write("\n[UNATTENDED SERVICES]\n")
    penalty = 0
    found = []
    for svc in ['ftp', 'telnet', 'nfs', 'snmpd']:
        if run_cmd(['ps', 'aux']).find(svc) != -1:
            found.append(svc)
    if found:
        report.write(f"Unattended risky services running: {', '.join(found)}\n")
        penalty += min(len(found)*5, 15)
    else:
        report.write("No risky unattended services found.\n")
    return penalty
