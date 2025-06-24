from .utils import run_cmd

def run_check(report, config):
    report.write("\n[WEAK PASSWORD POLICY]\n")
    penalty = 0
    pw_minlen = None
    pw_complex = False
    try:
        with open('/etc/login.defs') as f:
            for line in f:
                if line.strip().startswith('PASS_MIN_LEN'):
                    pw_minlen = int(line.split()[1])
    except Exception:
        pass
    try:
        with open('/etc/pam.d/common-password') as f:
            for line in f:
                if 'minlen=' in line or 'ucredit=' in line or 'lcredit=' in line or 'dcredit=' in line or 'ocredit=' in line:
                    pw_complex = True
    except Exception:
        pass
    if pw_minlen is not None and pw_minlen < 8:
        report.write("Weak password minimum length (<8)\n")
        penalty += 10
    elif not pw_complex:
        report.write("No password complexity enforced\n")
        penalty += 5
    else:
        report.write("Password policy is adequate.\n")
    return penalty
