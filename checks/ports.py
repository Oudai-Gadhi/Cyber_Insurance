from .utils import run_cmd
import time

def run_check(report, config):
    report.write("\n[PORT ANALYSIS]\n")
    mode = config.get('mode', 'quick')
    max_ports = config.get('max_ports', 25)
    nmap_file = config.get('nmap_file', 'nmap_scan.txt')
    penalty = 0
    open_ports = set()
    mgmt_ports = {'22': 'SSH', '23': 'Telnet', '80': 'HTTP', '443': 'HTTPS', '3389': 'RDP', '5900': 'VNC', '3306': 'MySQL', '5432': 'Postgres', '8080': 'HTTP-alt'}
    found_mgmt = []
    if mode == 'quick':
        report.write("Quick Scan (Listening Ports Only):\n")
        ss = run_cmd(['ss', '-tuln'])
        for line in ss.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 4:
                port = parts[4].split(':')[-1]
                open_ports.add(port)
        for p in list(open_ports)[:max_ports]:
            report.write(f"  - Port {p}\n")
    else:
        if not run_cmd(['which', 'nmap']):
            report.write("Nmap not available - quick scan results:\n")
            ss = run_cmd(['ss', '-tuln'])
            for line in ss.splitlines()[1:]:
                parts = line.split()
                if len(parts) > 4:
                    port = parts[4].split(':')[-1]
                    open_ports.add(port)
            for p in open_ports:
                report.write(f"  - Port {p}\n")
            return penalty
        report.write("Comprehensive Nmap Scan Results:\n")
        start = time.time()
        run_cmd(["nmap", "-p-", "-T4", "--min-rate", "1000", "-oN", nmap_file, "localhost"], shell=False, capture=False)
        duration = int(time.time() - start)
        report.write(f"\n\nScan completed in {duration} seconds\n")
        with open(nmap_file) as f:
            lines = [l for l in f if 'open' in l][:max_ports]
            for l in lines:
                # Try to extract port number
                parts = l.split()
                if len(parts) > 0 and '/' in parts[0]:
                    port = parts[0].split('/')[0]
                    open_ports.add(port)
                    report.write(f"  - {l.strip()}\n")
    # Management ports penalty
    for port, name in mgmt_ports.items():
        if port in open_ports:
            found_mgmt.append(f"{port} ({name})")
    if found_mgmt:
        report.write(f"\nWARNING: Open management ports detected: {', '.join(found_mgmt)}\n")
        penalty += 5
    # Penalty for too many open ports
    if len(open_ports) > 20:
        report.write(f"\nWARNING: High number of open ports detected: {len(open_ports)}\n")
        penalty += 10
    elif len(open_ports) > 10:
        report.write(f"\nNote: Moderate number of open ports: {len(open_ports)}\n")
        penalty += 5
    # Penalty for any port <1024 (well-known ports) except 22, 80, 443
    risky_ports = [p for p in open_ports if p.isdigit() and int(p) < 1024 and p not in ['22','80','443']]
    if risky_ports:
        report.write(f"\nWARNING: Unusual well-known ports open: {', '.join(risky_ports)}\n")
        penalty += 5
    return penalty
