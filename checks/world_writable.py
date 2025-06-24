from .utils import run_cmd

def run_check(report, config):
    report.write("\n[WORLD-WRITABLE FILES]\n")
    penalty = 0
    world_writable = run_cmd(['find', '/', '-xdev', '-not', '-path', '/tmp/*', '-perm', '-0002', '-type', 'f'])
    ww_files = [f for f in world_writable.splitlines() if f]
    if ww_files:
        report.write("World-writable files detected (excluding /tmp):\n")
        for f in ww_files[:10]:
            report.write(f"  - {f}\n")
        penalty += min(len(ww_files)*2, 15)
    else:
        report.write("No world-writable files found outside /tmp.\n")
    return penalty
