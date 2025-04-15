import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict, Counter

def analyze(directory):
    magic_summary = {}
    gadget_offset_map = defaultdict(list)
    gadget_types = ["br_x16", "ret", "ldr_x16"]

    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(directory, fname)) as f:
            lines = f.readlines()
            for line in lines:
                entry = json.loads(line.strip())
                magic = entry["magic"]
                jit_addr = entry["jit_addr"]
                gadgets = entry.get("gadgets", {})

                if magic not in magic_summary:
                    magic_summary[magic] = {
                        "total_runs": 0,
                        "unique_jit_addrs": set(),
                        "gadget_counts": Counter(),
                    }

                magic_summary[magic]["total_runs"] += 1
                magic_summary[magic]["unique_jit_addrs"].add(jit_addr)

                for gtype in gadget_types:
                    for off in gadgets.get(gtype, []):
                        magic_summary[magic]["gadget_counts"][gtype] += 1
                        gadget_offset_map[(magic, gtype)].append(off)

    # Save CSV summary
    rows = []
    for magic in magic_summary:
        summary = magic_summary[magic]
        row = {
            "magic": magic,
            "total_runs": summary["total_runs"],
            "unique_jit_addrs": len(summary["unique_jit_addrs"]),
        }
        for gtype in gadget_types:
            row[f"{gtype}_count"] = summary["gadget_counts"][gtype]
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv("gadget_summary_fixed.csv", index=False)

    # Draw histogram of offsets for each gadget
    plt.figure(figsize=(10, 6))
    for gtype in gadget_types:
        all_offsets = []
        for magic in magic_summary:
            all_offsets.extend(gadget_offset_map[(magic, gtype)])
        if all_offsets:
            plt.hist(all_offsets, bins=100, alpha=0.6, label=gtype)
    plt.legend()
    plt.xlabel("Gadget Offset")
    plt.ylabel("Frequency")
    plt.title("Gadget Offset Distribution (All Magic Values)")
    plt.tight_layout()
    plt.savefig("gadget_summary_fixed.png")

if __name__ == "__main__":
    analyze("jit_random_logs")
