import json
import matplotlib.pyplot as plt
from pathlib import Path
from collections import defaultdict

# 로그 디렉토리 설정
LOG_DIR = Path("./jit_random_logs")
OUTPUT_PDF = "gadget_distribution_combined_corrected.pdf"

# 각 run에서의 gadget 개수를 저장
gadget_counts_per_region = {
    "ret": [],
    "br_x16": [],
    "ldr_x16": []
}

# 로그 파일 파싱
for file in LOG_DIR.glob("*.jsonl"):
    with file.open() as f:
        for line in f:
            try:
                entry = json.loads(line)
                gadgets = entry.get("gadgets", {})
                for gadget_type in ["ret", "br_x16", "ldr_x16"]:
                    count = len(gadgets.get(gadget_type, []))
                    gadget_counts_per_region[gadget_type].append(count)
            except json.JSONDecodeError:
                continue

# 히스토그램 출력
plt.figure(figsize=(10, 6))
plt.hist(gadget_counts_per_region["ret"], bins=20, alpha=0.7, label='ret', edgecolor='black')
plt.hist(gadget_counts_per_region["br_x16"], bins=20, alpha=0.7, label='br x16', edgecolor='black')
plt.hist(gadget_counts_per_region["ldr_x16"], bins=20, alpha=0.7, label='ldr x16', edgecolor='black')

plt.title("Gadget Count Distribution per 8KB JIT Region (All Magic Values Combined)")
plt.xlabel("Number of Gadgets per Region")
plt.ylabel("Frequency")
plt.legend()
plt.grid(axis='y', linestyle='--', linewidth=0.5)
plt.tight_layout()
plt.savefig(OUTPUT_PDF)

print(f"[+] Saved graph to: {OUTPUT_PDF}")
