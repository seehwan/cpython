import json
import os
import matplotlib.pyplot as plt
from pathlib import Path
from collections import defaultdict
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# Config
LOG_DIR = "./jit_random_logs"
OUTPUT_PDF = "./distinct_gadget_histogram.pdf"

# Capstone disassembler
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

# Analyze gadget uniqueness by disassembling each 4-byte chunk
def count_unique_gadgets(gadget_addrs):
    unique_ops = set()
    for addr_hex in gadget_addrs:
        try:
            addr_int = int(addr_hex, 16)
            code_bytes = addr_int.to_bytes(8, byteorder='little')[:4]  # simulate 4B instruction
            for insn in md.disasm(code_bytes, addr_int):
                key = (insn.mnemonic, insn.op_str)
                unique_ops.add(key)
        except Exception:
            continue
    return len(unique_ops)

# Main execution
gadget_types = ["ret", "br_x16", "ldr_x16"]
results = defaultdict(list)

for file in Path(LOG_DIR).glob("*.jsonl"):
    with file.open() as f:
        for line in f:
            try:
                entry = json.loads(line)
                gadgets = entry.get("gadgets", {})
                for gtype in gadget_types:
                    count = count_unique_gadgets(gadgets.get(gtype, []))
                    results[gtype].append(count)
            except Exception:
                continue

# Plot histogram
plt.figure(figsize=(10, 6))
for gtype in gadget_types:
    plt.hist(results[gtype], bins=20, alpha=0.7, label=f"{gtype} (unique)", edgecolor='black')

plt.title("Distinct Gadget Count per 8KB JIT Region (Capstone Disassembly)")
plt.xlabel("Number of Unique Gadgets per Region")
plt.ylabel("Frequency")
plt.legend()
plt.grid(axis='y', linestyle='--', linewidth=0.5)
plt.tight_layout()
plt.savefig(OUTPUT_PDF)

print(f"[+] Saved histogram to: {OUTPUT_PDF}")
