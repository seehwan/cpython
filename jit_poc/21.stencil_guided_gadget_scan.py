import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

# Capstone setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "blr", "cmp", "eor", "orr", "add", "sub", "mov", "ldr"]
highlight_regs = ["x16", "x30", "pc"]

# ✅ emit 함수 기반 + profiling-friendly 구조 포함
def spray_add(x, y):
    acc = x + y
    for i in range(1000):
        acc += i ^ y
    return acc

def spray_sub(x, y):
    acc = x - y
    for i in range(1000):
        acc -= i ^ x
    return acc

def spray_mul(x, y):
    acc = x * y
    for i in range(1000):
        acc ^= acc * 2 + i
    return acc

def spray_ret(x):
    acc = x
    for i in range(1000):
        acc += i
    return acc

# 실험 함수 목록
emit_funcs = {
    "add": (spray_add, (42, 1)),
    "sub": (spray_sub, (42, 1)),
    "mul": (spray_mul, (42, 2)),
    "ret": (spray_ret, (123,)),
}

# JIT + gadget 스캔 루틴
def run_emit_scan(name, fn, args):
    pid = current_process().pid
    print(f"\n=== [PID {pid}] Scanning: {name} ===")

    for _ in range(5000):
        fn(*args)

    try:
        jit_addr = jitexecleak.leak_executor_jit(fn)
        print(f"[{name}] executor->jit_code @ 0x{jit_addr:x}")
    except RuntimeError:
        print(f"[{name}] Failed to JIT.")
        return

    mem = ctypes.string_at(jit_addr, 0x400)
    print(f"[{name}] Disassembling 0x{jit_addr:x} - 0x{jit_addr + 0x400:x}")
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
    for name, (fn, args) in emit_funcs.items():
        p = Process(target=run_emit_scan, args=(name, fn, args))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()
