# import os
# import json
# import pandas as pd
# import matplotlib.pyplot as plt
# from collections import defaultdict, Counter

# def analyze(directory):
#     magic_summary = {}
#     gadget_offset_map = defaultdict(list)
#     gadget_types = ["br_x16", "ret", "ldr_x16"]

#     for fname in sorted(os.listdir(directory)):
#         if not fname.endswith(".jsonl"):
#             continue
#         with open(os.path.join(directory, fname)) as f:
#             lines = f.readlines()
#             for line in lines:
#                 entry = json.loads(line.strip())
#                 magic = entry["magic"]
#                 jit_addr = entry["jit_addr"]
#                 gadgets = entry.get("gadgets", {})

#                 if magic not in magic_summary:
#                     magic_summary[magic] = {
#                         "total_runs": 0,
#                         "unique_jit_addrs": set(),
#                         "gadget_counts": Counter(),
#                     }

#                 magic_summary[magic]["total_runs"] += 1
#                 magic_summary[magic]["unique_jit_addrs"].add(jit_addr)

#                 for gtype in gadget_types:
#                     for off in gadgets.get(gtype, []):
#                         magic_summary[magic]["gadget_counts"][gtype] += 1
#                         gadget_offset_map[(magic, gtype)].append(off)

#     # Save CSV summary
#     rows = []
#     for magic in magic_summary:
#         summary = magic_summary[magic]
#         row = {
#             "magic": magic,
#             "total_runs": summary["total_runs"],
#             "unique_jit_addrs": len(summary["unique_jit_addrs"]),
#         }
#         for gtype in gadget_types:
#             row[f"{gtype}_count"] = summary["gadget_counts"][gtype]
#         rows.append(row)

#     df = pd.DataFrame(rows)
#     df.to_csv("gadget_summary_fixed.csv", index=False)

#     # Draw histogram of offsets for each gadget
#     plt.figure(figsize=(10, 6))
#     for gtype in gadget_types:
#         all_offsets = []
#         for magic in magic_summary:
#             all_offsets.extend(gadget_offset_map[(magic, gtype)])
#         if all_offsets:
#             plt.hist(all_offsets, bins=100, alpha=0.6, label=gtype)
#     plt.legend()
#     plt.xlabel("Gadget Offset")
#     plt.ylabel("Frequency")
#     plt.title("Gadget Offset Distribution (All Magic Values)")
#     plt.tight_layout()
#     plt.savefig("gadget_summary_fixed.png")

# if __name__ == "__main__":
#     analyze("jit_random_logs")

import os
import json
import matplotlib.pyplot as plt
from collections import defaultdict

LOG_DIR = "jit_random_logs"
GADGET_BYTES = {
    "ldr x16": b"\x50\x00\x00\x58",  # optional; include only if you're scanning this
    "ret": b"\xc0\x03\x5f\xd6",
    "br x16": b"\x00\x02\x1f\xd6",
}

def parse_offsets():
    all_offsets = defaultdict(list)
    for fname in os.listdir(LOG_DIR):
        if not fname.endswith(".jsonl"):
            continue
        path = os.path.join(LOG_DIR, fname)
        with open(path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    for gtype, offsets in entry["gadgets"].items():
                        all_offsets[gtype].extend(offsets)
                except Exception as e:
                    print(f"[!] Failed to parse {fname}: {e}")
    return all_offsets

def plot_gadget_offsets(offsets_dict):
    plt.figure(figsize=(10, 6))
    for gtype, offsets in offsets_dict.items():
        if not offsets:
            continue
        rel_offsets = [int(x, 16) % 0x1000 for x in offsets]  # relative offset within page
        plt.hist(rel_offsets, bins=50, alpha=0.6, label=gtype)

    plt.title("Gadget Offset Distribution (All Magic Values)")
    plt.xlabel("Offset (within 4KB JIT page)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.savefig("gadget_offset_distribution_all_magic.png")
    print("[+] Saved gadget_offset_distribution_all_magic.png")

if __name__ == "__main__":
    offsets = parse_offsets()
    plot_gadget_offsets(offsets)
