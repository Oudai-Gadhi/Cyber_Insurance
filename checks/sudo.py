from .utils import run_cmd, detect_distro
import os

def run_check(report, config):
    report.write("\n[SUDO PERMISSIONS AUDIT]\n")
    penalty = 0
    # Check for passwordless sudo for non-root users
    sudoers = run_cmd(['grep', '-r', '^[^#].*ALL=(ALL:ALL).*NOPASSWD', '/etc/sudoers'])
    if sudoers:
        report.write("WARNING: Passwordless sudo granted (Risk: CRITICAL):\n")
        report.write(sudoers)
        penalty += 10
    # Check for wildcards in sudoers
    wild = run_cmd(['grep', '-r', '.*\*.*', '/etc/sudoers'])
    if wild:
        report.write("WARNING: Wildcard commands in sudoers (Risk: HIGH):\n")
        report.write(wild)
        penalty += 5
    # Check for sudo access to shells or editors
    shell_cmds = ['bash', 'sh', 'zsh', 'ksh', 'dash', 'csh', 'tcsh', 'vim', 'nano', 'vi', 'python', 'perl']
    for cmd in shell_cmds:
        shell_access = run_cmd(['grep', '-r', cmd, '/etc/sudoers'])
        if shell_access:
            report.write(f"WARNING: Sudo access to shell/editor ({cmd}) detected (Risk: HIGH):\n")
            report.write(shell_access)
            penalty += 3
    # Check for ALL=ALL for non-root users
    all_all = run_cmd(['grep', '-r', 'ALL=ALL', '/etc/sudoers'])
    if all_all:
        report.write("WARNING: Sudoers entry with ALL=ALL detected (Risk: HIGH):\n")
        report.write(all_all)
        penalty += 3
    # Check for sudo group membership
    sudo_group = run_cmd(['getent', 'group', 'sudo'])
    if sudo_group:
        users = sudo_group.split(':')[-1].strip()
        if users:
            report.write(f"Users in sudo group: {users}\n")
            if 'root' not in users:
                penalty += 2
    # Alpine doas.conf
    if detect_distro() == 'alpine' and os.path.exists('/etc/doas.conf'):
        doas = run_cmd(['grep', '^permit nopass', '/etc/doas.conf'])
        if doas:
            report.write("WARNING: Passwordless doas configured (Risk: CRITICAL)\n")
            penalty += 10
    # Cap penalty
    return min(penalty, 20)
