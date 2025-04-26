import subprocess
import os
import re

SYSCALLS = ["mprotect", "mmap", "execve", "execveat", "mremap", "ptrace"]

def run_command(cmd, require_sudo=False):
    """Run command, adding sudo only if required and not already root"""
    if require_sudo and os.geteuid() != 0 and cmd[0] != "sudo":
        cmd.insert(0, "sudo")
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()

def check_apparmor():
    print("[AppArmor       ] Checking AppArmor status...")
    try:
        output = run_command(["aa-status"], require_sudo=True)
        enforce_profiles = re.search(r"(\d+)\s+profiles are in enforce mode", output)
        python_profile = "/usr/local/bin/python3.14" in output
        if enforce_profiles:
            print(f"[AppArmor       ] ✅ {enforce_profiles.group(1)} profiles in enforce mode")
        else:
            print("[AppArmor       ] ❌ Not in enforce mode")
        print("[AppArmor profile] ✅ Loaded for Python3.14"
              if python_profile else "[AppArmor profile] ❌ Not loaded for Python3.14")
    except Exception as e:
        print(f"[AppArmor       ] ❌ Error: {e}")

def check_seccomp():
    print("[Seccomp         ] Checking seccomp mode...")
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    mode = int(line.strip().split()[1])
                    if mode == 0:
                        print("[Seccomp         ] ✅ Disabled (mode 0)")
                    elif mode == 1:
                        print("[Seccomp         ] ⚠️  Strict mode (1)")
                    elif mode == 2:
                        print("[Seccomp         ] ⚠️  Filter mode (2)")
                    else:
                        print(f"[Seccomp         ] ❓ Unknown mode: {mode}")
                    return
        print("[Seccomp         ] ❌ Not found")
    except Exception as e:
        print(f"[Seccomp         ] ❌ Error: {e}")

def check_auditd():
    print("[Auditd          ] Checking auditd status...")
    try:
        status = subprocess.check_output(["systemctl", "is-active", "auditd"],
                                         stderr=subprocess.STDOUT).decode().strip()
        if status == "active":
            print("[Auditd          ] ✅ Running (systemd)")
        else:
            print(f"[Auditd          ] ❌ Status: {status}")
    except subprocess.CalledProcessError:
        print("[Auditd          ] ❌ Not running or not installed")

def apply_syscall_rules():
    print("[Auditd rules    ] ➕ Applying missing syscall rules...")
    for syscall in SYSCALLS:
        try:
            run_command(["auditctl", "-a", "exit,always", "-F", "arch=b64", "-S", syscall], require_sudo=True)
            print(f"✅ Rule added for: {syscall}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to add rule for {syscall}: {e}")
        except Exception as e:
            print(f"❌ Exception adding rule for {syscall}: {e}")

def check_auditd_rules():
    print("[Auditd rules    ] Checking syscall audit rules...")
    try:
        rules_output = run_command(["auditctl", "-l"], require_sudo=True)
        syscall_rules = [line for line in rules_output.splitlines() if re.search(r"-S\s+\w+", line)]

        if syscall_rules:
            print(f"[Auditd rules    ] ✅ Found {len(syscall_rules)} syscall rules")
        else:
            print("[Auditd rules    ] ❌ No syscall rules — applying now")
            apply_syscall_rules()

    except subprocess.CalledProcessError as e:
        print(f"[Auditd rules    ] ❌ Error: {e.output.decode().strip()}")
    except Exception as e:
        print(f"[Auditd rules    ] ❌ Exception: {e}")

if __name__ == "__main__":
    print("=== [ Trampoline Overwrite Experiment Pre-Check + Auto Patch ] ===")
    check_apparmor()
    check_seccomp()
    check_auditd()
    check_auditd_rules()
