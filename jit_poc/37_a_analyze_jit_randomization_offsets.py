import os
import json
import matplotlib.pyplot as plt
from collections import defaultdict

INPUT_DIR = "jit_random_logs"
SUMMARY_TXT = "jit_gadget_offset_summary.txt"
PLOT_FILE = "jit_gadget_offset_histogram.png"

GADGET_TYPES = ["ret", "br_x16", "ldr_x16"]

def parse_json_logs():
    data = defaultdict(lambda: defaultdict(list))  # magic → gadget_type → [offsets]
    for fname in os.listdir(INPUT_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(INPUT_DIR, fname)
        with open(path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    magic = entry["magic"]
                    for gadget, infos in entry["gadgets"].items():
                        for g in infos:
                            offset = int(g["offset"], 16)
                            data[magic][gadget].append(offset)
                except Exception as e:
                    print(f"Failed to parse line in {fname}: {e}")
    return data

def save_text_summary(data):
    with open(SUMMARY_TXT, "w") as f:
        for magic in sorted(data.keys()):
            f.write(f"=== [ Magic: {magic} ] ===\n")
            for gadget in GADGET_TYPES:
                offsets = data[magic][gadget]
                f.write(f"  {gadget:8}: {len(offsets)} gadgets\n")
                if offsets:
                    samples = ", ".join(hex(o) for o in sorted(offsets[:5]))
                    f.write(f"    Sample offsets: {samples} ...\n")
            f.write("\n")

def plot_histograms(data):
    fig, axs = plt.subplots(len(GADGET_TYPES), 1, figsize=(10, 4 * len(GADGET_TYPES)))
    for i, gadget in enumerate(GADGET_TYPES):
        ax = axs[i]
        for magic in sorted(data.keys()):
            offsets = data[magic][gadget]
            if not offsets:
                continue
            ax.hist(offsets, bins=32, alpha=0.6, label=magic, histtype='stepfilled')
        ax.set_title(f"Gadget Offset Histogram: {gadget}")
        ax.set_xlabel("Offset (bytes)")
        ax.set_ylabel("Frequency")
        ax.legend()
    plt.tight_layout()
    plt.savefig(PLOT_FILE)
    print(f"[+] Saved histogram to {PLOT_FILE}")

def main():
    print("[*] Analyzing gadget offsets...")
    data = parse_json_logs()
    save_text_summary(data)
    plot_histograms(data)
    print(f"[+] Saved summary to {SUMMARY_TXT}")

if __name__ == "__main__":
    main()
