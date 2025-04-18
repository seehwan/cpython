import ctypes
import mmap
import struct
import os

# Load shellcode (base64로 인코딩된 binary 파일)
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()
print(f"[+] Loaded shellcode: {len(shellcode)} bytes")

# Allocate RWX memory using mmap
libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p
sc_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
ctypes.memmove(sc_addr, shellcode, len(shellcode))
print(f"[+] Shellcode mmap @ 0x{sc_addr:x}")

# Allocate trampoline region (RWX도 가능, shellcode 앞에 위치)
tramp_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
print(f"[+] Trampoline mmap @ 0x{tramp_addr:x} (→ shellcode)")

# Create trampoline code:
# ldr x16, [pc, #8]
# br  x16
# .quad shellcode address
trampoline = (
    b"\x50\x00\x00\x58" +         # ldr x16, [pc, #8]
    b"\x00\x02\x1f\xd6" +         # br x16
    struct.pack("<Q", sc_addr)    # target shellcode address
)
ctypes.memmove(tramp_addr, trampoline, len(trampoline))

# Execute the trampoline using function cast
print("[*] Jumping to trampoline (via overwrite)...")
shell_func_type = ctypes.CFUNCTYPE(None)
shell_func = shell_func_type(tramp_addr)
shell_func()  # 실제 실행
