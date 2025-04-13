import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

# Capstone disassembler
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "blr", "cmp", "eor", "orr", "add", "sub", "mov", "ldr"]
highlight_regs = ["x16", "x30", "pc"]

# Step 1: gadget-prone hot functions
def gadget_add(x, y):
    acc = x + y
    for i in range(100):
        acc = ((acc ^ y) + (x | i)) ^ (acc >> 1)
        if i % 7 == 0:
            acc += i * x
    return acc

def gadget_xor(x, y):
    acc = x ^ y
    for i in range(80):
        acc ^= (i * y) + x
        if i % 9 == 0:
            acc -= i
    return acc

def gadget_cmp(x, y):
    acc = 0
    for i in range(60):
        if x > (i ^ y):
            acc += x
        else:
            acc -= y
    return acc

def gadget_mix(x, y):
    acc = x
    for i in range(100):
        acc ^= (x + i) & y
        if i % 11 == 0:
            acc |= (x ^ y) + i
    return acc

# 함수 이름 → 함수 정의 mapping
spray_funcs = {
    "gadget_add": (gadget_add, (42, 1)),
    "gadget_xor": (gadget_xor, (42, 0xFF)),
    "gadget_cmp": (gadget_cmp, (42, 17)),
    "gadget_mix": (gadget_mix, (0xF0F0F0F0, 42)),
}

# 실험 루틴: trigger + disasm
def run_jit_scan(name, fn, args):
    pid = current_process().pid
    print(f"\n=== [PID {pid}] JIT scan for: {name} ===")

    for _ in range(5000):
        fn(*args)

    try:
        jit_addr = jitexecleak.leak_executor_jit(fn)
        print(f"[{name}] executor->jit_code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[{name}] Failed to JIT")
        return

    mem = ctypes.string_at(jit_addr, 0x400)
    print(f"[{name}] Disassembling 0x{jit_addr:x} - 0x{jit_addr+0x400:x}")
    for i in md.disasm(mem, jit_addr):
        if i.mnemonic in interesting or any(r in i.op_str for r in highlight_regs):
            print(f"  [GADGET] 0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")
        else:
            print(f"            0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")

# 병렬 실행
if __name__ == "__main__":
    try:
        set_start_method("fork")
    except RuntimeError:
        pass

    procs = []
    for name, (fn, args) in spray_funcs.items():
        p = Process(target=run_jit_scan, args=(name, fn, args))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()
