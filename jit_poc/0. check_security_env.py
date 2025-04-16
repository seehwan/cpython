import subprocess
import os

def check_apparmor():
    try:
        output = subprocess.check_output(["aa-status"], stderr=subprocess.STDOUT).decode()
        enforce_mode = "profiles are in enforce mode" in output
        python_profile = "/usr/local/bin/python3.14" in output
        print("[AppArmor   ] ✅ OK" if enforce_mode else "[AppArmor   ] ❌ Not in enforce mode")
        print("[AppArmor profile] ✅ OK" if python_profile else "[AppArmor profile] ❌ Not loaded")
    except Exception as e:
        print(f"[AppArmor   ] ❌ Error: {e}")

def check_seccomp():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    mode = int(line.strip().split()[1])
                    if mode == 0:
                        print("[Seccomp   ] ✅ OK (disabled)")
                    elif mode == 1:
                        print("[Seccomp   ] ⚠️  Strict mode")
                    elif mode == 2:
                        print("[Seccomp   ] ⚠️  Filter mode")
                    else:
                        print(f"[Seccomp   ] ❓ Unknown mode: {mode}")
                    return
        print("[Seccomp   ] ❌ Not found")
    except Exception as e:
        print(f"[Seccomp   ] ❌ Error: {e}")

def check_auditd():
    try:
        output = subprocess.check_output(["pidof", "auditd"]).decode().strip()
        if output:
            print("[Auditd     ] ✅ OK")
        else:
            print("[Auditd     ] ❌ Not running")
    except subprocess.CalledProcessError:
        print("[Auditd     ] ❌ Not running")

def check_auditd_rules():
    try:
        cmd = ["auditctl", "-l"]
        if os.geteuid() != 0:
            cmd.insert(0, "sudo")
        rules = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        if "-S " in rules or "-a always" in rules:
            print("[Auditd rules] ✅ Found syscall rules")
        else:
            print("[Auditd rules] ❌ No syscall rules")
    except subprocess.CalledProcessError as e:
        print(f"[Auditd rules] ❌ Error: {e.output.decode().strip()}")
    except Exception as e:
        print(f"[Auditd rules] ❌ Exception: {e}")

if __name__ == "__main__":
    print("=== [ Trampoline Overwrite Experiment Pre-Check ] ===")
    check_apparmor()
    check_seccomp()
    check_auditd()
    check_auditd_rules()
