from .utils import run_cmd, detect_distro

def run_check(report, config):
    report.write("\n[SUID BINARIES AUDIT]\n")
    penalty = 0
    basic_suid = [
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/pkexec", "/bin/su", "/bin/mount",
        "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp"
    ]
    if detect_distro() == 'alpine':
        basic_suid.append("/usr/bin/doas")
    found = run_cmd(['find', '/', '-type', 'f', '-perm', '-4000'])
    dangerous = []
    world_writable = []
    suspicious = []
    for binary in found.splitlines():
        b = binary.strip()
        if b not in basic_suid:
            # Check for world-writable SUID
            perms = run_cmd(['ls', '-l', b])
            if 'w' in perms.split()[0][8]:
                world_writable.append(b)
            # Check for known dangerous SUID binaries
            if any(x in b for x in ['nmap', 'perl', 'python', 'find', 'vim', 'nano', 'cp', 'mv', 'bash', 'sh', 'dash', 'zsh', 'ksh']):
                suspicious.append(b)
            dangerous.append(b)
    if dangerous:
        report.write("Non-standard SUID binaries (Risk: HIGH):\n")
        for b in dangerous:
            report.write(f"  - {b}\n")
        if suspicious:
            report.write("\nSUID binaries with known exploitation risk:\n")
            for b in suspicious:
                report.write(f"  - {b}\n")
        if world_writable:
            report.write("\nWorld-writable SUID binaries (CRITICAL!):\n")
            for b in world_writable:
                report.write(f"  - {b}\n")
            penalty += 10
        penalty += min(len(dangerous)*2, 10)
        if suspicious:
            penalty += min(len(suspicious)*2, 10)
    else:
        report.write("No unusual SUID binaries found.\n")
    return min(penalty, 20)
