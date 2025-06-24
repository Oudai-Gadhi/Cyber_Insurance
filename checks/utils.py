# Utility functions for distro, package manager, and color output
import platform
import subprocess
import os

ANSI = {
    'RED': '\033[0;31m',
    'GREEN': '\033[0;32m',
    'YELLOW': '\033[0;33m',
    'BLUE': '\033[0;34m',
    'NC': '\033[0m',
}

def detect_distro():
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line.strip().split('=')[1].replace('"','')
        return platform.system().lower()
    except Exception:
        return 'unknown'

def detect_pkg_manager():
    distro = detect_distro()
    if distro in ['debian','ubuntu','kali','pop']:
        return 'deb'
    elif distro in ['centos','rhel','fedora','almalinux','rocky']:
        return 'rpm'
    elif distro in ['arch','manjaro']:
        return 'arch'
    elif distro == 'alpine':
        return 'apk'
    else:
        return 'unknown'

def run_cmd(cmd, shell=False, capture=True):
    try:
        if capture:
            return subprocess.check_output(cmd, shell=shell, stderr=subprocess.DEVNULL, text=True)
        else:
            subprocess.run(cmd, shell=shell)
            return ''
    except Exception:
        return ''

def color(text, color):
    return f"{ANSI.get(color,'')}" + text + f"{ANSI['NC']}"
