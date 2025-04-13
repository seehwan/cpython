import ctypes
import struct

# Constants
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20
PAGE_SIZE = 0x1000

libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p

# Step 1: mmap RWX memory
mem = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
if mem in (0, -1):
    raise RuntimeError("[-] mmap failed")

print(f"[+] RWX memory allocated at: 0x{mem:x}")

# Step 2: Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

# Step 3: Define address layout
trampoline_addr = mem                    # trampoline starts here
literal_addr = trampoline_addr + 8       # where the .quad will go
shellcode_addr = literal_addr + 8        # shellcode starts here

print(f"[+] Trampoline @ 0x{trampoline_addr:x}")
print(f"[+] Literal @ 0x{literal_addr:x}")
print(f"[+] Shellcode @ 0x{shellcode_addr:x}")

# Step 4: Build trampoline (PC-relative literal jump)
trampoline = (
    b"\x50\x00\x00\x58" +                 # ldr x16, [pc, #8]
    b"\x00\x02\x1f\xd6" +                 # br x16
    struct.pack("<Q", shellcode_addr)    # jump target literal
)

# Step 5: Merge trampoline + shellcode
full_payload = trampoline + shellcode
ctypes.memmove(mem, full_payload, len(full_payload))
print("[*] Trampoline + shellcode written")

# Step 6: Execute trampoline
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(mem)
print("[*] Jumping to trampoline...")
fn()
