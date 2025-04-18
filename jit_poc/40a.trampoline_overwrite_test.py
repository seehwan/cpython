import ctypes
import struct
import sys
import os

print("=== [ Trampoline Overwrite Shellcode Test ] ===")

# 1. 입력 파일로부터 shellcode 로드
if len(sys.argv) < 2:
    print("Usage: python3.14 40a.trampoline_overwrite_test.py <shellcode.bin>")
    sys.exit(1)

path = sys.argv[1]
with open(path, "rb") as f:
    bcode = f.read()
print(f"[+] Loaded binary code: {len(bcode)} bytes")

# 2. RWX mmap 영역에 binary code 저장
libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p
sc_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
ctypes.memmove(sc_addr, bcode, len(bcode))
print(f"[+] Binary code mmap @ 0x{sc_addr:x}")

# Allocate trampoline region (RWX도 가능, shellcode 앞에 위치)
tramp_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
print(f"[+] Trampoline mmap @ 0x{tramp_addr:x} (→ binary code)")

# Create trampoline code:
# ldr x16, [pc, #8]
# br  x16
# .quad shellcode address
trampoline = (
    b"\x50\x00\x00\x58" +         # ldr x16, [pc, #8]
    b"\x00\x02\x1f\xd6" +         # br x16
    struct.pack("<Q", sc_addr)    # target binary code address
)
ctypes.memmove(tramp_addr, trampoline, len(trampoline))
print(f"[+] Trampoline @ 0x{tramp_addr:x} → binary code")

# 4. Binary code 실행 (x16 = binary code, br x16)
print("[*] Jumping to trampoline (via overwrite)...")

try:
    fn = ctypes.CFUNCTYPE(None)(tramp_addr)
    fn()
except Exception as e:
    print(f"[!] Exception occurred: {e}")
