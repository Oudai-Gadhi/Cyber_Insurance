from .utils import run_cmd
import os

def run_check(report, config):
    report.write("\n[CRONJOB VULNERABILITIES]\n")
    penalty = 0
    cron_dirs = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d", "/var/spool/cron/crontabs", "/etc/crontabs"]
    for dir in cron_dirs:
        if os.path.isdir(dir):
            files = run_cmd(['find', dir, '-type', 'f', '-perm', '-0002', '!', '-user', 'root'])
            if files:
                report.write(f"WARNING: World-writable cronjobs in {dir} (Risk: HIGH):\n")
                report.write(files)
                penalty += 5
    return min(penalty, 10)
