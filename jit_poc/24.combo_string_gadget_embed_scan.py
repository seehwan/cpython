import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

# Capstone config
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "ldr", "mov", "cmp", "ands"]
highlight_regs = ["x16", "x30", "pc"]

# Known raw gadgets
known_gadgets = {
    b"\x00\x02\x1f\xd6": "br x16",
    b"\xc0\x03\x5f\xd6": "ret",
}

# Magic values to vary int operations
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

def make_combo_func(magic):
    def combo(x: int, s: str):
        acc = x
        g = b'\x00\x02\x1f\xd6'.decode('latin1')  # br x16 gadget string
        for i in range(3000):
            acc ^= (magic & i)
            acc += (acc << 1)
            acc &= 0x0F0F0F0F
            s += str(i)
            s = s.replace("123", g)
        return s.upper()
    return combo

def run_magic_combo(magic):
    pid = current_process().pid
    print(f"\n=== [PID {pid}] Testing magic: 0x{magic:08x} ===")
    combo = make_combo_func(magic)

    for _ in range(6000):
        combo(42, "123AA")

    try:
        jit_addr = jitexecleak.leak_executor_jit(combo)
        print(f"[0x{magic:08x}] executor->jit_code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[0x{magic:08x}] Failed to JIT.")
        return

    length = 0x2000
    mem = ctypes.string_at(jit_addr, length)

    # Capstone scan
    for i in md.disasm(mem, jit_addr):
        if i.mnemonic in interesting or any(r in i.op_str for r in highlight_regs):
            print(f"  [GADGET] 0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")

    # Raw gadget scan
    raw = bytearray(mem)
    for i in range(len(raw) - 4):
        chunk = raw[i:i+4]
        if bytes(chunk) in known_gadgets:
            addr = jit_addr + i
            print(f"  [RAW-GADGET] {known_gadgets[bytes(chunk)]} @ 0x{addr:x}")

if __name__ == "__main__":
    try:
        set_start_method("fork")
    except RuntimeError:
        pass

    procs = []
    for magic in magic_values:
        p = Process(target=run_magic_combo, args=(magic,))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()
