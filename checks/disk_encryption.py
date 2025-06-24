from .utils import run_cmd

def run_check(report, config):
    report.write("\n[DISK ENCRYPTION STATUS]\n")
    penalty = 0
    lsblk = run_cmd(['lsblk', '-o', 'NAME,FSTYPE'])
    if 'crypt' not in lsblk:
        report.write("No disk encryption detected\n")
        penalty += 10
    else:
        report.write("Disk encryption detected.\n")
    return penalty
