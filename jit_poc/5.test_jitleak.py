import jitexecleak

def hot_loop(x):
    total = 0
    for i in range(100_000):
        if i % 17 == 0:
            total += x * i
        elif i % 7 == 0:
            total -= x // 2
        else:
            total ^= i
    return total

for _ in range(10000):
    hot_loop(42)

addr = jitexecleak.leak_executor_jit(hot_loop)
print(f"[+] Leaked executor JIT code addr: 0x{addr:x}")

import dis
dis.show_code(hot_loop)
