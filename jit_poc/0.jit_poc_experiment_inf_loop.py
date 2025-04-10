import os
import ctypes
import jitremap
import mmap
import time

# Constants
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

# 1. 반복 함수 정의 (JIT 대상)
def hot_func(x):
    total = 0
    for _ in range(100_000):
        total += x * 2
    return total

# 2. JIT 트리거
print("[*] Triggering JIT...")
for _ in range(100):
    hot_func(42)

# 3. /proc/self/maps에서 JIT 코드 캐시 주소 찾기
def find_jit_code_ranges():
    results = []
    with open("/proc/self/maps") as f:
        for line in f:
            if "r-xp" in line and ("jit" in line.lower() or "/anon" in line.lower() or "[anon" in line):
                parts = line.split()
                start_str, end_str = parts[0].split('-')
                start = int(start_str, 16)
                end = int(end_str, 16)
                results.append((start, end, end - start))
    return results

jit_ranges = find_jit_code_ranges()
print("[*] Found JIT code ranges:")
for r in jit_ranges:
    print(f"  0x{r[0]:x}-0x{r[1]:x} ({r[2]} bytes)")

if not jit_ranges:
    raise RuntimeError("[!] JIT code range not found!")

# 4. 첫 번째 JIT 주소로 시도
jit_addr, _, _ = jit_ranges[0]
page_size = 0x1000

# 5. mprotect로 RWX 설정 시도
print("[*] Attempting to mprotect JIT region to RWX...")
res = jitremap.remap(jit_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC)
print("    =>", res)

# 6. shellcode 삽입 (NOP sled + infinite loop)
shellcode = b"\x1f\x20\x03\xd5" * 4  # ARM64 NOP
shellcode += b"\x00\x00\x00\x14"     # B . (branch to self)
print("[*] Writing shellcode to JIT memory...")
ctypes.memmove(jit_addr, shellcode, len(shellcode))

# 7. shellcode 실행 (ctypes jump)
print("[*] Executing shellcode via function pointer jump...")
FUNC_TYPE = ctypes.CFUNCTYPE(None)
shell_fn = FUNC_TYPE(jit_addr)
shell_fn()  # should loop forever if successful

