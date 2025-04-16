import subprocess
import os
import shutil

def print_status(name, status, msg=""):
    icon = "✅ OK" if status else f"❌ {msg}"
    print(f"[{name:<10}] {icon}")

def check_apparmor():
    print("[AppArmor   ] Checking status (user mode)...")
    try:
        output = subprocess.check_output(["aa-status"], stderr=subprocess.STDOUT).decode()
        enforce = "profiles are in enforce mode" in output
        has_profile = "/usr/local/bin/python3.14" in output
        print_status("AppArmor", enforce, "not enforcing")
        print_status("AppArmor profile", has_profile, "Not found")
    except Exception as e:
        print_status("AppArmor", False, f"Error: {e}")

def check_seccomp():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    mode = int(line.strip().split()[1])
                    print_status("Seccomp", mode == 0, f"Mode {mode}")
                    return
        print_status("Seccomp", False, "Not found")
    except Exception as e:
        print_status("Seccomp", False, f"Error: {e}")

def check_auditd():
    print("[Auditd     ] Checking status...")
    try:
        result = subprocess.run(["systemctl", "is-active", "auditd"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            print_status("Auditd", False, "Not running. Trying install...")
            install_auditd()
        else:
            print_status("Auditd", True)

        # Check rules
        rules = subprocess.check_output(["sudo", "auditctl", "-l"]).decode()
        if "-S mmap" in rules:
            print_status("Auditd rules", True)
        else:
            print_status("Auditd rules", False, "No syscall rules")
    except Exception as e:
        print_status("Auditd", False, f"Error: {e}")

def install_auditd():
    if not shutil.which("auditd"):
        print("[Install    ] Installing auditd...")
        subprocess.call(["sudo", "apt-get", "update"])
        subprocess.call(["sudo", "apt-get", "install", "-y", "auditd", "audispd-plugins"])
    subprocess.call(["sudo", "systemctl", "enable", "--now", "auditd"])
    subprocess.call([
        "sudo", "auditctl", "-a", "exit,always",
        "-F", "arch=b64", "-S", "mmap", "-S", "mprotect", "-S", "ptrace", "-k", "jit-experiment"
    ])

def main():
    print("=== [ Trampoline Overwrite Experiment Pre-Check ] ===")
    check_apparmor()
    check_seccomp()
    check_auditd()

if __name__ == "__main__":
    main()
