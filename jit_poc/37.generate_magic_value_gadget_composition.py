import json
import matplotlib.pyplot as plt
from pathlib import Path
from collections import defaultdict

# 로그 파일이 있는 디렉토리
LOG_DIR = Path("./jit_random_logs")
OUTPUT_FILE = "magic_value_gadget_composition.pdf"

# 수집용 딕셔너리
gadget_counts = defaultdict(lambda: {"ret": 0, "br_x16": 0, "ldr_x16": 0})
magic_run_counts = defaultdict(int)

# 로그 파일 파싱
for file in LOG_DIR.glob("*.jsonl"):
    with file.open() as f:
        for line in f:
            try:
                entry = json.loads(line)
                magic = entry.get("magic")
                if not magic:
                    continue
                magic_run_counts[magic] += 1
                for gtype in ["ret", "br_x16", "ldr_x16"]:
                    gadget_list = entry.get("gadgets", {}).get(gtype, [])
                    gadget_counts[magic][gtype] += len(gadget_list)
            except Exception:
                continue

# 그래프용 데이터 정렬
sorted_magics = sorted(gadget_counts.keys(), key=lambda x: int(x, 16))
ret_ratios = []
br_ratios = []
ldr_ratios = []

for magic in sorted_magics:
    total = sum(gadget_counts[magic].values())
    if total == 0:
        ret_ratios.append(0)
        br_ratios.append(0)
        ldr_ratios.append(0)
    else:
        ret_ratios.append(gadget_counts[magic]["ret"] / total)
        br_ratios.append(gadget_counts[magic]["br_x16"] / total)
        ldr_ratios.append(gadget_counts[magic]["ldr_x16"] / total)

# Stacked Bar Chart 생성
x = range(len(sorted_magics))
plt.figure(figsize=(10, 6))
plt.bar(x, ldr_ratios, label="ldr x16", color="lightcoral")
plt.bar(x, br_ratios, bottom=ldr_ratios, label="br x16", color="steelblue")
bottom_layer = [ldr + br for ldr, br in zip(ldr_ratios, br_ratios)]
plt.bar(x, ret_ratios, bottom=bottom_layer, label="ret", color="darkgray")

plt.xticks(x, sorted_magics, rotation=45)
plt.ylabel("Gadget Type Ratio")
plt.title("Gadget Type Composition by Magic Value")
plt.legend()
plt.tight_layout()
plt.savefig(OUTPUT_FILE)

print(f"[+] Saved: {OUTPUT_FILE}")
