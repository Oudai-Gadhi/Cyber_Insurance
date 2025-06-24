import os
import sys
import datetime
import argparse
from checks import firewall, services, patches, suid, sudo, cron, network, ports, \
    password_policy, guest_accounts, root_ssh, world_writable, unattended_services, disk_encryption
from checks.utils import color

REPORT_FILE = f"cyber_risk_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
NMAP_FILE = f"nmap_scan_{datetime.datetime.now().strftime('%Y%m%d')}.txt"
SCAN_MODE = sys.argv[1] if len(sys.argv) > 1 else 'quick'
MAX_PORTS_TO_SHOW = 25
RISK_THRESHOLD = 70

HEADER = f"""=== PROFESSIONAL CYBER INSURANCE RISK ASSESSMENT ===\nReport Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nAssessment Mode: {SCAN_MODE.upper()}\nKernel Version: {os.uname().release}\nHostname: {os.uname().nodename}\n==================================================="""

def main():
    parser = argparse.ArgumentParser(description="Cyber Insurance Risk Assessment Tool")
    parser.add_argument('mode', nargs='?', default='quick', choices=['quick', 'full'], help='Scan mode: quick or full (default: quick)')
    parser.add_argument('--insured-value', type=int, default=100_000, help='Total insurable value in USD (default: 100000)')
    args = parser.parse_args()

    scan_mode = args.mode
    total_insurable_value = args.insured_value

    print(color("=== Cyber Insurance Risk Assessment ===", 'BLUE'))
    print(f"Mode: {color(scan_mode.upper(), 'YELLOW')} scan selected")
    with open(REPORT_FILE, 'w') as report:
        report.write(HEADER + '\n')
        # Run checks
        penalties = {}
        # Assign weights for each risk category (insurance-aligned, more realistic)
        WEIGHTS = {
            'patches': 0.18,              # Patch management is critical
            'firewall': 0.12,             # Firewall is highly weighted
            'services': 0.10,             # Critical services
            'suid': 0.10,                 # Privilege escalation risk
            'sudo': 0.10,                 # Privileged access
            'network': 0.10,              # Network exposure
            'ports': 0.10,                # Port exposure
            'password_policy': 0.06,      # Password policy
            'guest_accounts': 0.04,       # Guest/anonymous accounts
            'root_ssh': 0.04,             # Root SSH login
            'world_writable': 0.02,       # World-writable files
            'unattended_services': 0.02,  # Unattended risky services
            'disk_encryption': 0.02,      # Disk encryption
            'cron': 0.00                  # Cron jobs (now considered low risk for insurance)
        }
        # Each check returns a penalty (0 = perfect, higher = worse)
        penalties['patches'] = patches.run_check(report, {'mode': scan_mode})
        penalties['firewall'] = firewall.run_check(report, {'mode': scan_mode})
        penalties['services'] = services.run_check(report, {'mode': scan_mode})
        penalties['suid'] = suid.run_check(report, {'mode': scan_mode})
        penalties['sudo'] = sudo.run_check(report, {'mode': scan_mode})
        penalties['network'] = network.run_check(report, {'mode': scan_mode})
        penalties['ports'] = ports.run_check(report, {'mode': scan_mode, 'max_ports': MAX_PORTS_TO_SHOW, 'nmap_file': NMAP_FILE})
        penalties['password_policy'] = password_policy.run_check(report, {'mode': scan_mode})
        penalties['guest_accounts'] = guest_accounts.run_check(report, {'mode': scan_mode})
        penalties['root_ssh'] = root_ssh.run_check(report, {'mode': scan_mode})
        penalties['world_writable'] = world_writable.run_check(report, {'mode': scan_mode})
        penalties['unattended_services'] = unattended_services.run_check(report, {'mode': scan_mode})
        penalties['disk_encryption'] = disk_encryption.run_check(report, {'mode': scan_mode})
        penalties['cron'] = cron.run_check(report, {'mode': scan_mode})
        # Calculate weighted score (insurance-aligned)
        # Each penalty is normalized (max penalty per check = 20)
        weighted_score = 0
        for k, v in penalties.items():
            max_penalty = 20  # You can tune this per check for realism
            normalized = max(0, 1 - min(v, max_penalty) / max_penalty)
            weighted_score += WEIGHTS.get(k, 0) * normalized
        score = int(weighted_score * 100)
        score = max(0, min(100, score))
        report.write(f"\n[RISK ASSESSMENT]\nOverall Security Score: {score}/100\n")
        # Recommendations
        report.write("\n[INSURANCE RECOMMENDATIONS]\n")
        report.write("1. [CORE] Minimum $1M cyber liability coverage\n")
        report.write("2. [CORE] Incident response retainer (with 24/7 support)\n")
        if penalties['patches'] > 0:
            report.write("3. [REQUIRED] Implement regular patch management and vulnerability scanning\n")
        if penalties['firewall'] > 0:
            report.write("4. [REQUIRED] Deploy and enforce a host-based firewall policy\n")
        if penalties['sudo'] > 0 or penalties['suid'] > 0:
            report.write("5. [REQUIRED] Review and restrict privileged access (sudo/SUID)\n")
        if penalties['password_policy'] > 0:
            report.write("6. [REQUIRED] Enforce strong password policies and MFA for all users\n")
        if penalties['root_ssh'] > 0:
            report.write("7. [REQUIRED] Disable root SSH login and use key-based authentication\n")
        if penalties['ports'] > 0 or penalties['network'] > 0:
            report.write("8. [RECOMMENDED] Minimize open ports and segment critical services\n")
        if penalties['disk_encryption'] > 0:
            report.write("9. [RECOMMENDED] Enable full disk encryption for sensitive data\n")
        if penalties['unattended_services'] > 0:
            report.write("10. [RECOMMENDED] Remove or secure unnecessary network services\n")
        if penalties['world_writable'] > 0:
            report.write("11. [RECOMMENDED] Audit and remediate world-writable files\n")
        if penalties['guest_accounts'] > 0:
            report.write("12. [RECOMMENDED] Remove or disable guest/anonymous accounts\n")
        if penalties['cron'] > 0:
            report.write("13. [RECOMMENDED] Review scheduled tasks for security risks\n")
        if score < 85:
            report.write("14. [RECOMMENDED] Add business interruption coverage\n")
        if score < RISK_THRESHOLD:
            report.write("15. [CRITICAL] Require a third-party security audit before policy issuance\n")

        # Risk band logic
        if score >= 85:
            risk_level = "Low"
            outcome = "Standard coverage, good rates"
            base_rate = 0.01
        elif score >= 70:
            risk_level = "Moderate"
            outcome = "Coverage with reasonable conditions"
            base_rate = 0.02
        elif score >= 50:
            risk_level = "High"
            outcome = "Expensive, may require preconditions"
            base_rate = 0.04
        else:
            risk_level = "Critical"
            outcome = "Coverage likely denied"
            base_rate = 0.10

        premium = int(total_insurable_value * base_rate)
        report.write(f"\n[RISK PROFILE]\nRisk Level: {risk_level}\nLikely Insurance Outcome: {outcome}\n")
        if score < 50:
            report.write("WARNING: Risk is critical. Insurance may be denied or only hypothetical pricing offered.\n")
        report.write(f"\n[PREMIUM ESTIMATE]\nTotal Insurable Value: ${total_insurable_value:,}\nEstimated Annual Premium: ${premium:,}\n")
    print(color("Assessment complete!", 'GREEN'))
    print(f"Full report: {color(REPORT_FILE, 'YELLOW')}")

if __name__ == '__main__':
    main()
