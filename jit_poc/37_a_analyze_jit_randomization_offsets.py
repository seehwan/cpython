import os
import json
from collections import defaultdict, Counter
import matplotlib.pyplot as plt

LOG_DIR = "jit_random_logs"
OUTPUT_TXT = "jit_analysis_summary.txt"

def load_all_entries():
    all_entries = []
    for fname in os.listdir(LOG_DIR):
        if not fname.endswith(".jsonl"):
            continue
        with open(os.path.join(LOG_DIR, fname)) as f:
            for line in f:
                all_entries.append(json.loads(line.strip()))
    return all_entries

def summarize(entries):
    addr_counter = Counter()
    gadget_counter = defaultdict(int)
    offset_histogram = defaultdict(list)
    magic_counts = defaultdict(int)

    for entry in entries:
        magic = entry["magic"]
        magic_counts[magic] += 1
        addr_counter[entry["jit_addr"]] += 1

        for gtype, offsets in entry["gadgets"].items():
            gadget_counter[gtype] += len(offsets)
            for off in offsets:
                offset = int(off, 16) - int(entry["jit_addr"], 16)
                offset_histogram[gtype].append(offset)

    return addr_counter, gadget_counter, magic_counts, offset_histogram

def print_summary(addr_counter, gadget_counter, magic_counts, offset_histogram):
    with open(OUTPUT_TXT, "w") as f:
        def out(line=""):
            print(line)
            f.write(line + "\n")

        out("=== [ JIT Randomization Summary ] ===")
        out(f"Total entries        : {sum(magic_counts.values())}")
        out(f"Unique JIT addresses : {len(addr_counter)}")
        out(f"Gadget type count    : {dict(gadget_counter)}")
        out(f"Magic run count      : {dict(magic_counts)}\n")

        out("=== [ Sample Gadget Offsets per Type ] ===")
        for gtype, offsets in offset_histogram.items():
            out(f"  {gtype} ({len(offsets)} offsets):")
            sample = sorted(offsets)[:5]
            out(f"    Sample offsets: {sample}\n")

def plot_offset_histograms(offset_histogram):
    for gtype, offsets in offset_histogram.items():
        if not offsets:
            continue
        plt.figure()
        plt.hist(offsets, bins=50, edgecolor='black')
        plt.title(f"Gadget Offset Distribution: {gtype}")
        plt.xlabel("Offset (bytes)")
        plt.ylabel("Frequency")
        plt.grid(True)
        plt.savefig(f"{gtype}_offset_histogram.png")

def main():
    entries = load_all_entries()
    addr_counter, gadget_counter, magic_counts, offset_histogram = summarize(entries)
    print_summary(addr_counter, gadget_counter, magic_counts, offset_histogram)
    plot_offset_histograms(offset_histogram)

if __name__ == "__main__":
    main()
