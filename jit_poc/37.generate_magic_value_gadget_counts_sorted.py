import json
import matplotlib.pyplot as plt
from pathlib import Path
from collections import defaultdict

# 로그 디렉토리 설정
LOG_DIR = Path("./jit_random_logs")
OUTPUT_PDF = "magic_value_gadget_counts_sorted.pdf"

# 각 magic 값별 gadget 개수 저장
gadget_totals = defaultdict(lambda: {"ret": 0, "br_x16": 0, "ldr_x16": 0})

# 로그 파일 파싱
for file in LOG_DIR.glob("*.jsonl"):
    with file.open() as f:
        for line in f:
            try:
                entry = json.loads(line)
                magic = entry.get("magic")
                if not magic:
                    continue
                for g in ["ret", "br_x16", "ldr_x16"]:
                    count = len(entry.get("gadgets", {}).get(g, []))
                    gadget_totals[magic][g] += count
            except json.JSONDecodeError:
                continue

# 정렬
sorted_magics = sorted(gadget_totals.keys(), key=lambda m: int(m, 16))
ret_vals = [gadget_totals[m]["ret"] for m in sorted_magics]
br_vals = [gadget_totals[m]["br_x16"] for m in sorted_magics]
ldr_vals = [gadget_totals[m]["ldr_x16"] for m in sorted_magics]

# 그래프 그리기
x = range(len(sorted_magics))
plt.figure(figsize=(10, 6))
plt.bar(x, ldr_vals, width=0.25, label="ldr x16", align="center", color="lightcoral")
plt.bar([i + 0.25 for i in x], br_vals, width=0.25, label="br x16", align="center", color="steelblue")
plt.bar([i + 0.5 for i in x], ret_vals, width=0.25, label="ret", align="center", color="darkgray")

plt.xticks([i + 0.25 for i in x], sorted_magics, rotation=45)
plt.ylabel("Gadget Count (Total across runs)")
plt.title("Total Gadget Counts by Magic Value (Numerically Sorted)")
plt.legend()
plt.tight_layout()
plt.savefig(OUTPUT_PDF)

print(f"[+] Saved graph to: {OUTPUT_PDF}")
