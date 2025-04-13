# jit_randomization_worker.py
import os
import sys
import json
import ctypes
from capstone import *
from jitexecleak import leak_executor_jit

# Output directory
LOG_DIR = "jit_random_logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Capstone AArch64 setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# Raw gadget patterns
raw_gadgets = {
    b"\x00\x02\x1f\xd6": "br x16",
    b"\xc0\x03\x5f\xd6": "ret",
}

# Hot function for spraying
def make_combo_func(magic):
    def combo(x: int, s: str):
        acc = x
        g = b'\x00\x02\x1f\xd6'.decode('latin1')  # br x16 opcode as string
        for i in range(3000):
            acc ^= (magic & i)
            acc += (acc << 1)
            acc &= 0x0F0F0F0F
            s += str(i)
            s = s.replace("123", g)
        return s.upper()
    return combo

# Parse JIT memory regions from /proc/self/maps
def get_jit_regions():
    regions = []
    with open("/proc/self/maps") as f:
        for line in f:
            if "r-xp" in line and ("jit" in line.lower() or "[anon]" in line):
                start, end = [int(x, 16) for x in line.split()[0].split("-")]
                regions.append((start, end))
    return regions

# Scan memory for raw gadget byte patterns
def scan_for_gadgets(mem, base):
    result = {"ret": [], "br_x16": [], "ldr_x16": []}
    for i in range(len(mem) - 4):
        chunk = mem[i:i+4]
        addr = base + i
        if chunk == b"\xc0\x03\x5f\xd6":
            result["ret"].append(addr)
        elif chunk == b"\x00\x02\x1f\xd6":
            result["br_x16"].append(addr)
        elif chunk[:3] == b"\x10\x00\x00":  # loose match for ldr x16, [pc, #imm]
            result["ldr_x16"].append(addr)
    return result

# Store experiment result to per-magic file in .jsonl format
def log_result(magic, run_id, jit_addr, gadget_offsets):
    path = os.path.join(LOG_DIR, f"jit_random_{magic:08x}.jsonl")
    entry = {
        "magic": f"0x{magic:08x}",
        "run_id": run_id,
        "pid": os.getpid(),
        "jit_addr": f"0x{jit_addr:x}",
        "gadgets": {k: [f"0x{a:x}" for a in v] for k, v in gadget_offsets.items()}
    }
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    if any(gadget_offsets.values()):
        print(f"[+] [magic=0x{magic:08x}] Found gadget(s) at JIT addr 0x{jit_addr:x}")
    else:
        print(f"[-] [magic=0x{magic:08x}] No gadget found (JIT addr 0x{jit_addr:x})")

# Single experiment execution
def run_worker(magic, run_id):
    print(f"\n[*] Worker running magic=0x{magic:08x}, run_id={run_id}, pid={os.getpid()}")
    combo = make_combo_func(magic)

    for _ in range(6000):  # Trigger JIT
        combo(42, "123AA")

    try:
        jit_addr = leak_executor_jit(combo)
    except RuntimeError:
        print(f"[!] [magic=0x{magic:08x}] JIT failed")
        return

    all_gadgets = {"ret": [], "br_x16": [], "ldr_x16": []}
    for start, end in get_jit_regions():
        mem = ctypes.string_at(start, end - start)
        gadgets = scan_for_gadgets(mem, start)
        for k, v in gadgets.items():
            all_gadgets[k].extend(v)

    log_result(magic, run_id, jit_addr, all_gadgets)

# CLI entry
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <magic:int> <run_id:int>")
        sys.exit(1)
    run_worker(int(sys.argv[1], 16), int(sys.argv[2]))
