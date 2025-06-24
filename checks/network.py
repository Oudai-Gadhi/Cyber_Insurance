from .utils import run_cmd

def run_check(report, config):
    report.write("\n[NETWORK TOPOLOGY RISK]\n")
    penalty = 0
    live_hosts = 0
    ipn = run_cmd(['ip', 'neigh'])
    if ipn:
        live_hosts = len(ipn.splitlines())
    else:
        arp = run_cmd(['arp', '-an'])
        if arp:
            live_hosts = len(arp.splitlines())
    report.write(f"Detected hosts on local network: {live_hosts}\n")
    if live_hosts > 20:
        penalty = 10
        report.write("WARNING: High-density network (Risk: MEDIUM)\n")
    elif live_hosts > 5:
        penalty = 5
        report.write("NOTE: Moderate network size\n")
    return penalty
