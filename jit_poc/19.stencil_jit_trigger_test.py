import ctypes
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

# Capstone disassembler
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "blr", "cmp", "eor", "orr", "add", "sub", "mov", "ldr"]
highlight_regs = ["x16", "x30", "pc"]

# ✅ 개선된 spray 함수들: 모든 iteration에서 연산 수행, 조건문 없음
def spray_add(x, y):
    acc = x
    for i in range(300):
        acc = (acc + y + i) ^ (acc >> 2)
    return acc

def spray_xor(x, y):
    acc = x
    for i in range(300):
        acc ^= y ^ (i * 3)
    return acc

def spray_mix(x, y):
    acc = x
    for i in range(300):
        acc += (acc ^ y) & 0xF0F0
        acc ^= (x + i)
    return acc

def spray_shift(x, y):
    acc = x
    for i in range(300):
        acc = ((acc << 1) ^ (y >> 1)) + i
    return acc

# 함수명 → 함수 정의 + 인자
spray_funcs = {
    "add": (spray_add, (42, 1)),
    "xor": (spray_xor, (42, 0xFF)),
    "mix": (spray_mix, (0xF0F0F0F0, 0xFFFF)),
    "shift": (spray_shift, (1234, 4321)),
}

# 실험 루틴: trigger + disasm
def run_jit_scan(name, fn, args):
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
