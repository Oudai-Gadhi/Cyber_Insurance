from .utils import run_cmd, detect_distro

def run_check(report, config):
    report.write("\n[CRITICAL SERVICES]\n")
    penalty = 0
    services = {'sshd': 'Remote access', 'auditd': 'System auditing', 'fail2ban': 'Brute-force protection'}
    distro = detect_distro()
    for service, desc in services.items():
        active = False
        if distro == 'alpine':
            status = run_cmd(['rc-status'])
            if service in status:
                active = True
        else:
            status = run_cmd(['systemctl', 'is-active', service])
            if 'active' in status:
                active = True
        if active:
            report.write(f"{service}: Active ({desc})\n")
        else:
            report.write(f"{service}: Inactive ({desc}) [Standard penalty]\n")
            penalty += 5
    return penalty
