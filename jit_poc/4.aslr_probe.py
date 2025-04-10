import ctypes
import sys

# Constants
PROT_READ = 1
PROT_WRITE = 2
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20
MREMAP_MAYMOVE = 1
PAGE_SIZE = 0x1000
MAP_FAILED = ctypes.c_void_p(-1).value

libc = ctypes.CDLL("libc.so.6")

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

shellcode_size = len(shellcode)
aligned_size = ((shellcode_size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

libc.mmap.restype = ctypes.c_void_p
mem = libc.mmap(None, aligned_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

mem_addr = ctypes.cast(mem, ctypes.c_void_p).value
if mem_addr is None or mem_addr == -1:
    sys.exit(1)
mem_addr &= 0xffffffffffffffff
ctypes.memmove(mem_addr, shellcode, shellcode_size)

libc.mremap.restype = ctypes.c_void_p
new_mem = libc.mremap(mem_addr, aligned_size, aligned_size, MREMAP_MAYMOVE)

new_addr = ctypes.cast(new_mem, ctypes.c_void_p).value
if new_addr is None or new_addr == -1:
    sys.exit(1)
new_addr &= 0xffffffffffffffff

print(f"{new_addr:#x}")

