from .utils import run_cmd, detect_pkg_manager
import os

def run_check(report, config):
    report.write("\n[PATCH MANAGEMENT]\n")
    penalty = 0
    pkg = detect_pkg_manager()
    if pkg == 'deb':
        last = run_cmd(['stat', '-c', '%y', '/var/lib/apt/periodic/update-success-stamp'])
        report.write(f"Last Update: {last.strip() or 'Unknown'}\n")
        upg = run_cmd(['apt', 'list', '--upgradable'])
        sec = [l for l in upg.splitlines() if 'security' in l or 'upgradable' in l]
        total_upg = len([l for l in upg.splitlines() if l and not l.startswith('Listing...')])
        report.write("Security/Important Updates Available:\n")
        for l in sec:
            report.write(f"  - {l}\n")
        if total_upg > 20:
            penalty = 25
        elif total_upg > 10:
            penalty = 15
        elif total_upg > 0:
            penalty = total_upg
    elif pkg == 'rpm':
        last = run_cmd(['stat', '-c', '%y', '/var/lib/yum/history/'])
        report.write(f"Last Update: {last.strip() or 'Unknown'}\n")
        upg = run_cmd(['yum', 'check-update'])
        sec = [l for l in upg.splitlines() if l and not l.startswith('Loaded plugins') and not l.startswith('Obsoleting')]
        report.write("Updates Available:\n")
        for l in sec:
            report.write(f"  - {l}\n")
        if len(sec) > 20:
            penalty = 25
        elif len(sec) > 10:
            penalty = 15
        elif len(sec) > 0:
            penalty = len(sec)
    elif pkg == 'apk':
        last = run_cmd(['stat', '-c', '%y', '/lib/apk/db/installed'])
        report.write(f"Last Update: {last.strip() or 'Unknown'}\n")
        upg = run_cmd(['apk', 'version', '-l', '<'])
        sec = [l for l in upg.splitlines() if l and not l.startswith('Upgrading')]
        report.write("Upgrades Available:\n")
        for l in sec:
            report.write(f"  - {l}\n")
        if len(sec) > 20:
            penalty = 25
        elif len(sec) > 10:
            penalty = 15
        elif len(sec) > 0:
            penalty = len(sec)
    else:
        report.write("Package manager not recognized - update checks skipped\n")
        return 5  # Small penalty for unknown state

    # Check for unattended-upgrades or automatic updates
    if pkg == 'deb':
        auto = run_cmd(['systemctl', 'is-enabled', 'unattended-upgrades'])
        if 'enabled' in auto:
            report.write("Automatic security updates: ENABLED\n")
        else:
            report.write("Automatic security updates: DISABLED\n")
            penalty += 5
    elif pkg == 'rpm':
        dnf_auto = run_cmd(['systemctl', 'is-enabled', 'dnf-automatic.timer'])
        if 'enabled' in dnf_auto:
            report.write("Automatic updates: ENABLED\n")
        else:
            report.write("Automatic updates: DISABLED\n")
            penalty += 5
    elif pkg == 'apk':
        # Alpine doesn't have built-in auto-updates, but check for cron jobs
        cron = run_cmd(['crontab', '-l'])
        if 'apk upgrade' in cron:
            report.write("Automatic updates: ENABLED (via cron)\n")
        else:
            report.write("Automatic updates: Not detected\n")
            penalty += 3

    return penalty
