import json
import pathlib

def process_results(results):
    success = sum(1 for r, _ in results if r == "success")
    fail = sum(1 for r, _ in results if r == "fail")
    total = len(results)

    # Calculate jump latency (average duration of successful executions)
    success_durations = [log["duration"] for r, log in results if r == "success"]
    avg_jump_latency = sum(success_durations) / len(success_durations) if success_durations else 0

    # Calculate stability (success rate)
    stability = (success / total) * 100 if total > 0 else 0

    # Calculate jitter (standard deviation of trampoline offsets)
    jit_addrs = [int(log["jit_addr"], 16) for r, log in results if r == "success"]
    if jit_addrs:
        base_addr = min(jit_addrs)
        jitters = [addr - base_addr for addr in jit_addrs]
        avg_jitter = sum(jitters) / len(jitters)
        std_jitter = (sum((x - avg_jitter) ** 2 for x in jitters) / len(jitters)) ** 0.5
    else:
        avg_jitter = std_jitter = 0

    print(f"\nExecution Summary:")
    print(f"Total runs: {total}")
    print(f"Success: {success} ({stability:.2f}%)")
    print(f"Fail: {fail}")
    print(f"\nPerformance Metrics:")
    print(f"Average jump latency: {avg_jump_latency:.6f} seconds")
    print(f"Trampoline jitter:")
    print(f"  Average: {avg_jitter} bytes")
    print(f"  Standard deviation: {std_jitter:.2f} bytes")
    print(f"Privilege level: user")

    # Log file with only essential metrics
    results_dir = pathlib.Path("trampoline_jit")
    results_dir.mkdir(exist_ok=True)
    with open(results_dir / "trampoline_overwrite.jsonl", "w") as f:
        for _, log in results:
            # Create a new log entry with only the required metrics
            new_log = {
                "jump_latency": log.get("duration", 0),
                "status": "success" if log.get("status") == "success" else "fail",
                "trampoline_jitter": int(log["jit_addr"], 16) - base_addr if "jit_addr" in log else 0,
                "privilege_level": "user"
            }
            f.write(json.dumps(new_log) + "\n") 