import ctypes
import os
import sys

try:
    from seccomp import SyscallFilter, ALLOW, KILL
except ImportError:
    print("[!] Please install python3-seccomp: sudo apt install python3-seccomp")
    sys.exit(1)

# Constants
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
PAGE_SIZE = 4096

# Load libc
libc = ctypes.CDLL("libc.so.6")

# Allocate RW memory
addr = libc.mmap(
    None, PAGE_SIZE,
    PROT_READ | PROT_WRITE,
    os.MAP_PRIVATE | os.MAP_ANONYMOUS,
    -1, 0
)
if addr == -1 or addr is None:
    raise RuntimeError("[-] mmap failed")

print(f"[+] mmap allocated at: 0x{addr:x}")

# ⛔️ Apply seccomp to block mprotect
print("[*] Installing seccomp filter to block mprotect...")
f = SyscallFilter(defaction=ALLOW)
f.add_rule(KILL, "mprotect")  # ⛔️ Block mprotect()
f.load()

# Try to set RWX (will trigger SIGSYS)
print("[*] Calling mprotect (should crash with SIGSYS)...")
result = libc.mprotect(addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC)

print("[?] mprotect returned:", result)

