#0. check_security_env.py
import os
import subprocess
from pathlib import Path

def check_apparmor_enabled():
    try:
        output = subprocess.check_output(["aa-status"], stderr=subprocess.DEVNULL).decode()
        enforce_lines = [line for line in output.splitlines() if "enforce" in line]
        python_line = [line for line in output.splitlines() if "/usr/local/bin/python3.14" in line]
        return ("enforce" in output, len(python_line) > 0)
    except Exception:
        return (False, False)

def check_seccomp_status():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    mode = int(line.strip().split()[-1])
                    return mode
        return -1
    except Exception:
        return -1

def check_auditd_status():
    try:
        output = subprocess.check_output(["auditctl", "-s"], stderr=subprocess.DEVNULL).decode()
        return "enabled 1" in output
    except Exception:
        return False

def check_audit_rules():
    try:
        output = subprocess.check_output(["auditctl", "-l"], stderr=subprocess.DEVNULL).decode()
        important = ["mmap", "mprotect", "ptrace"]
        found = [s for s in important if s in output]
        return found
    except Exception:
        return []

def print_summary():
    print("=== [ Trampoline Overwrite Experiment Pre-Check ] ===")

    aa_enforce, aa_profile = check_apparmor_enabled()
    print(f"[AppArmor] enforce mode: {'✅ OK' if aa_enforce else '❌ Not enforced'}")
    print(f"[AppArmor] python3.14 profile loaded: {'✅ OK' if aa_profile else '❌ Not found'}")

    seccomp = check_seccomp_status()
    print(f"[Seccomp] Mode: {seccomp} → {'✅ OK' if seccomp in [0,2] else '❌'}")

    audit_on = check_auditd_status()
    print(f"[Auditd] Status: {'✅ enabled' if audit_on else '❌ not enabled'}")

    rules = check_audit_rules()
    print(f"[Auditd] Syscall rules: {'✅ ' + ', '.join(rules) if rules else '❌ none'}")

if __name__ == "__main__":
    print_summary()
