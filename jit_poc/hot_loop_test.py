def hot_loop():
    acc = 0
    for i in range(10_000_000):
        acc += i
    return acc

hot_loop()
input("Check JIT mappings now (press Enter to continue)...")

