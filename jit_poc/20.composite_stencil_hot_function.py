import ctypes
import jitexecleak
from capstone import *

# Capstone setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
interesting = ["ret", "br", "blr", "cmp", "eor", "orr", "add", "sub", "mov", "ldr"]
highlight_regs = ["x16", "x30", "pc"]

# ✅ 다양한 stencil 유도 연산 포함 (add, xor, cmp, or, shift, return)
def composite_hot(x, y):
    acc = x + y                   # _BINARY_OP_ADD_INT
    acc ^= y                     # _BINARY_OP_XOR_INT
    acc |= x                     # _BINARY_OP_OR_INT
    for i in range(100):         # loop으로 branch 유도
        acc = (acc + i) ^ (acc >> 1)
        acc &= (x | (y << 1))
    if x > y:                    # _COMPARE_OP_INT
        acc += 42
    return acc                   # _RETURN_VALUE

# JIT trigger
for _ in range(5000):
    composite_hot(42, 1337)

# Leak JIT address
jit_addr = jitexecleak.leak_executor_jit(composite_hot)
print(f"[+] executor->jit_code @ 0x{jit_addr:x}")

# Disassemble
mem = ctypes.string_at(jit_addr, 0x400)
print(f"[*] Disassembling 0x{jit_addr:x} - 0x{jit_addr + 0x400:x}")
for i in md.disasm(mem, jit_addr):
    if i.mnemonic in interesting or any(r in i.op_str for r in highlight_regs):
        print(f"  [GADGET] 0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")
    else:
        print(f"            0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")
