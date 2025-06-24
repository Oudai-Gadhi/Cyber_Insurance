from .utils import run_cmd, color

def run_check(report, config):
    report.write("\n[FIREWALL STATUS]\n")
    penalty = 0
    firewall_found = False
    # UFW (Ubuntu/Debian)
    if run_cmd(['which', 'ufw']):
        status = run_cmd(['sudo', 'ufw', 'status'])
        if 'active' in status:
            report.write("UFW: Active\n")
            rules = run_cmd(['sudo', 'ufw', 'status', 'numbered'])
            open_ports = [l for l in rules.splitlines() if 'ALLOW' in l]
            report.write(f"UFW Open Ports: {len(open_ports)}\n")
            if len(open_ports) > 5:
                report.write("WARNING: Many open ports in UFW!\n")
                penalty += 5
        else:
            report.write("UFW: Inactive\n")
            penalty += 20
        firewall_found = True
    # firewalld (RHEL/Fedora)
    if not firewall_found and run_cmd(['which', 'firewall-cmd']):
        status = run_cmd(['sudo', 'firewall-cmd', '--state'])
        if 'running' in status:
            report.write("Firewalld: Active\n")
            zones = run_cmd(['sudo', 'firewall-cmd', '--get-active-zones'])
            for zone in zones.split():
                if zone and zone != 'interfaces:':
                    ports = run_cmd(['sudo', 'firewall-cmd', '--zone', zone, '--list-ports'])
                    if ports.strip():
                        report.write(f"Zone {zone} open ports: {ports.strip()}\n")
                        if len(ports.split()) > 5:
                            report.write("WARNING: Many open ports in firewalld!\n")
                            penalty += 5
        else:
            report.write("Firewalld: Inactive\n")
            penalty += 20
        firewall_found = True
    # iptables/nftables (Generic/Advanced)
    if not firewall_found:
        ipt = run_cmd(['sudo', 'iptables', '-L', '-n'])
        nft = run_cmd(['sudo', 'nft', 'list', 'ruleset'])
        ipt_custom = ipt and 'Chain INPUT (policy ACCEPT)' not in ipt
        nft_custom = nft and 'chain input' in nft
        if ipt_custom:
            report.write("IPTables: Custom Rules Detected\n")
            open_ports = [l for l in ipt.splitlines() if 'ACCEPT' in l and '0.0.0.0/0' in l]
            report.write(f"IPTables open ACCEPT rules: {len(open_ports)}\n")
            if len(open_ports) > 5:
                report.write("WARNING: Many open iptables rules!\n")
                penalty += 5
        elif nft_custom:
            report.write("NFTables: Rules Detected\n")
            open_ports = [l for l in nft.splitlines() if 'accept' in l]
            report.write(f"NFTables accept rules: {len(open_ports)}\n")
            if len(open_ports) > 5:
                report.write("WARNING: Many open nftables rules!\n")
                penalty += 5
        else:
            report.write("No Active Firewall Detected\n")
            penalty += 20
    # Check for default policies (should be DROP or REJECT)
    if run_cmd(['which', 'iptables']):
        policies = run_cmd(['sudo', 'iptables', '-L'])
        for line in policies.splitlines():
            if 'policy' in line:
                if 'ACCEPT' in line:
                    report.write(f"WARNING: Default policy is ACCEPT: {line}\n")
                    penalty += 5
                elif 'DROP' in line or 'REJECT' in line:
                    report.write(f"Good: Default policy is {line}\n")
    # Check for open management ports (22, 3389, 5900, etc.)
    open_mgmt_ports = []
    for port in ['22', '3389', '5900', '8080', '8000']:
        if run_cmd(['sudo', 'ss', '-tuln']).find(f':{port} ') != -1:
            open_mgmt_ports.append(port)
    if open_mgmt_ports:
        report.write(f"WARNING: Open management ports detected: {', '.join(open_mgmt_ports)}\n")
        penalty += 5
    return penalty
