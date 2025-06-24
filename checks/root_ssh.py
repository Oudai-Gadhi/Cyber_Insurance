from .utils import run_cmd

def run_check(report, config):
    report.write("\n[ROOT SSH LOGIN]\n")
    penalty = 0
    sshd = run_cmd(['grep', '^PermitRootLogin', '/etc/ssh/sshd_config'])
    if 'yes' in sshd:
        report.write("PermitRootLogin enabled in SSH config\n")
        penalty += 10
    else:
        report.write("Root SSH login is disabled.\n")
    return penalty
