import time

def hot_loop():
    acc = 0
    for i in range(10_000_000):  # JIT을 확실히 유도하기 위해 루프 증가
        acc += i
    return acc

for _ in range(3):
    hot_loop()

print("\n[*] Sleeping for inspection... check `/proc/self/maps` now!")
time.sleep(10)

# 모든 실행 가능한 영역 출력
print("\n[*] === Executable Memory Regions (r-xp/rwxp) ===")
with open("/proc/self/maps", "r") as f:
    for line in f:
        if "r-xp" in line or "rwxp" in line:
            print(line.strip())