import json
from collections import defaultdict
import matplotlib.pyplot as plt

results_file = "trampoline_offset_experiment.jsonl"

stats = defaultdict(lambda: {"success": 0, "fail": 0, "times": []})

with open(results_file) as f:
    for line in f:
        entry = json.loads(line)
        offset = entry.get("trampoline_offset")
        if not offset:
            continue
        if entry["status"] == "success":
            stats[offset]["success"] += 1
            stats[offset]["times"].append(entry.get("exec_time_ms", 0))
        else:
            stats[offset]["fail"] += 1

offsets = sorted(stats.keys())
success_counts = [stats[o]["success"] for o in offsets]
fail_counts = [stats[o]["fail"] for o in offsets]
avg_times = [sum(stats[o]["times"]) / len(stats[o]["times"]) if stats[o]["times"] else 0 for o in offsets]

# Plot 1: Success count per offset
plt.figure(figsize=(10, 4))
plt.bar([hex(o) for o in offsets], success_counts, color='green', label='Successes')
plt.bar([hex(o) for o in offsets], fail_counts, bottom=success_counts, color='red', label='Failures')
plt.title("Trampoline Execution Success per Offset")
plt.xlabel("Offset (hex)")
plt.ylabel("Count")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("offset_success_distribution.png")

# Plot 2: Average execution time
plt.figure(figsize=(10, 4))
plt.plot([hex(o) for o in offsets], avg_times, marker='o')
plt.title("Average Execution Time per Offset")
plt.xlabel("Offset (hex)")
plt.ylabel("Avg exec time (ms)")
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.savefig("offset_exec_time.png")

print("✅ Analysis complete. Plots saved:")
print(" - offset_success_distribution.png")
print(" - offset_exec_time.png")
