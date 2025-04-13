import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "ldr", "mov", "cmp", "ands"]
highlight_regs = ["x16", "x30", "pc"]
known_gadgets = {
    b"\x00\x02\x1f\xd6": "br x16",
    b"\xc0\x03\x5f\xd6": "ret",
}

# Define multiple structurally different hot functions to diversify JIT regions
def spray_add(x):
    acc = x
    for i in range(3000): acc += i ^ x
    return acc

def spray_xor(x):
    acc = x
    for i in range(3000): acc ^= (x + i)
    return acc

def spray_shift(x):
    acc = x
    for i in range(3000): acc = (acc << 1) ^ (acc >> 2)
    return acc

def spray_and_mix(x):
    acc = x
    for i in range(3000): acc = ((acc & 0xF0F0F0F0) | i) ^ x
    return acc

def spray_combo(x):
    acc = x
    for i in range(3000):
        acc ^= (i + x)
        acc = (acc << 1) + (acc >> 3)
        acc &= 0xFFFFFFFF
    return acc

spray_funcs = {
    "add": spray_add,
    "xor": spray_xor,
    "shift": spray_shift,
    "and_mix": spray_and_mix,
    "combo": spray_combo,
}

def get_jit_regions():
    regions = []
    with open("/proc/self/maps") as f:
        for line in f:
            if "r-xp" in line and ("jit" in line.lower() or "[anon]" in line):
                parts = line.split()
                start, end = [int(x, 16) for x in parts[0].split("-")]
                regions.append((start, end))
    return regions

def scan_region(start, end):
    print(f"[*] Scanning JIT region: 0x{start:x}-0x{end:x} ({end - start} bytes)")
    mem = ctypes.string_at(start, end - start)
    for i in md.disasm(mem, start):
        if i.mnemonic in interesting or any(r in i.op_str for r in highlight_regs):
            print(f"  [GADGET] 0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")
    raw = bytearray(mem)
    for i in range(len(raw) - 4):
        chunk = raw[i:i+4]
        if bytes(chunk) in known_gadgets:
            addr = start + i
            print(f"  [RAW-GADGET] {known_gadgets[bytes(chunk)]} @ 0x{addr:x}")

def run_spray(name, fn):
    pid = current_process().pid
    print(f"\n=== [PID {pid}] Running spray: {name} ===")
    for _ in range(6000): fn(42)
    try:
        jit_addr = jitexecleak.leak_executor_jit(fn)
        print(f"[{name}] executor->jit_code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[{name}] Failed to JIT.")
        return
    for start, end in get_jit_regions():
        scan_region(start, end)

if __name__ == "__main__":
    try: set_start_method("fork")
    except RuntimeError: pass
    procs = []
    for name, fn in spray_funcs.items():
        p = Process(target=run_spray, args=(name, fn))
        p.start()
        procs.append(p)
    for p in procs: p.join()
