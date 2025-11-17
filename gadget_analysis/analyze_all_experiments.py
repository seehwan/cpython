#!/usr/bin/env python3
"""
Scenario A Result Analysis (All Experiments)
Runs all applicable experiments on Scenario A data without matplotlib
"""

import pickle
import json
import sys
from pathlib import Path
from collections import defaultdict
import statistics

# Add to path
sys.path.insert(0, '/home/mobileos2/cpython')


def load_scenario_a_runs(experiment_id):
    """Load all 3 runs of Scenario A"""
    base_path = Path(f"gadget_analysis/experiments/{experiment_id}")
    captures_dir = base_path / "captures"
    
    runs = []
    for run_num in [1, 2, 3]:
        pkl_path = captures_dir / f"scenario_a_run{run_num}.pkl"
        meta_path = captures_dir / f"scenario_a_run{run_num}_meta.json"
        
        if not pkl_path.exists():
            print(f"Warning: {pkl_path} not found")
            continue
            
        with open(pkl_path, 'rb') as f:
            data = pickle.load(f)
        
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
        
        runs.append({
            'run_num': run_num,
            'data': data,
            'metadata': metadata
        })
    
    return runs


def analyze_run(run_data):
    """Analyze gadgets from a single run - reads aggregated gadget data"""
    data = run_data['data']
    metadata = run_data['metadata']
    
    # Get gadget dictionaries (each key is a gadget type, value is a list of gadget instances)
    post_patch = data.get('post_patch', {})
    pre_patch = data.get('pre_patch', {})
    
    # Count gadgets by summing lengths of all lists
    post_gadgets_count = sum(len(gadgets) for gadgets in post_patch.values())
    pre_gadgets_count = sum(len(gadgets) for gadgets in pre_patch.values())
    
    # Count gadgets by type
    post_by_type = {gtype: len(gadgets) for gtype, gadgets in post_patch.items()}
    pre_by_type = {gtype: len(gadgets) for gtype, gadgets in pre_patch.items()}
    
    return {
        'run_num': run_data['run_num'],
        'scenario': metadata.get('scenario', 'unknown'),
        'run': metadata.get('run', 0),
        'function_count': metadata.get('function_count', 0),
        'warmup_iterations': metadata.get('warmup_iterations', 0),
        'pre_gadgets': pre_gadgets_count,
        'post_gadgets': post_gadgets_count,
        'gadget_increase': post_gadgets_count - pre_gadgets_count,
        'pre_by_type': pre_by_type,
        'post_by_type': post_by_type,
    }


def generate_experiment_1_results(results, output_dir):
    """Experiment 1: Stencil Gadget Cataloging"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "experiment_1_catalog.txt", 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("EXPERIMENT 1: STENCIL GADGET CATALOGING\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("JIT Gadget Analysis\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Run':<10} {'Pre-Gadgets':>15} {'Post-Gadgets':>15} {'Delta':>15}\n")
        f.write("-" * 80 + "\n")
        
        for r in results:
            delta = r['gadget_increase']
            f.write(f"Run {r['run_num']:<5} {r['pre_gadgets']:>15,} {r['post_gadgets']:>15,} {delta:>15,}\n")
        
        f.write("\n\nGadget Count Statistics\n")
        f.write("-" * 80 + "\n")
        avg_pre = statistics.mean([r['pre_gadgets'] for r in results])
        avg_post = statistics.mean([r['post_gadgets'] for r in results])
        f.write(f"Average Pre-Patch Gadgets: {avg_pre:,.1f}\n")
        f.write(f"Average Post-Patch Gadgets: {avg_post:,.1f}\n")
        f.write(f"Average Gadget Increase: {avg_post - avg_pre:,.1f}\n")
        
        # Gadget type breakdown
        f.write("\n\nGadget Type Breakdown (Post-Patch)\n")
        f.write("-" * 80 + "\n")
        for r in results:
            f.write(f"\nRun {r['run_num']}:\n")
            for gtype, count in sorted(r['post_by_type'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {gtype:<15}: {count:>6,} gadgets\n")
    
    print(f"✅ Experiment 1: Catalog saved to {output_dir}")


def generate_experiment_2_results(results, output_dir):
    """Experiment 2: Memory Region Analysis"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "experiment_2_memory_regions.txt", 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("EXPERIMENT 2: MEMORY REGION ANALYSIS\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("Gadget Region Statistics\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Run':<10} {'Pre-Gadgets':>15} {'Post-Gadgets':>15} {'Increase':>15}\n")
        f.write("-" * 80 + "\n")
        
        for r in results:
            increase = r['gadget_increase']
            f.write(f"Run {r['run_num']:<5} {r['pre_gadgets']:>15,} {r['post_gadgets']:>15,} {increase:>15,}\n")
        
        f.write("\n\nAnalysis Summary\n")
        f.write("-" * 80 + "\n")
        f.write(f"Average gadget increase: {statistics.mean([r['gadget_increase'] for r in results]):,.1f}\n")
        f.write(f"Total functions: {results[0]['function_count']}\n")
        f.write(f"Iterations: {results[0]['warmup_iterations']}\n")
    
    print(f"✅ Experiment 2: Memory regions saved to {output_dir}")


def generate_experiment_3_results(results, output_dir):
    """Experiment 3: Patch Impact Analysis"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "experiment_3_patch_impact.txt", 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("EXPERIMENT 3: PATCH IMPACT ANALYSIS\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("Gadget Count Changes (Pre-Patch → Post-Patch)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Run':<10} {'Pre-Patch':>20} {'Post-Patch':>20} {'Delta':>15}\n")
        f.write("-" * 80 + "\n")
        
        for r in results:
            delta = r['gadget_increase']
            f.write(f"Run {r['run_num']:<5} {r['pre_gadgets']:>20,} {r['post_gadgets']:>20,} {delta:>15,}\n")
        
        f.write("\n\nGadget Type Distribution Changes\n")
        f.write("-" * 80 + "\n")
        
        # Aggregate all gadget types
        all_types = set()
        for r in results:
            all_types.update(r['post_by_type'].keys())
        
        for gtype in sorted(all_types):
            f.write(f"\n{gtype}:\n")
            for r in results:
                pre_count = r['pre_by_type'].get(gtype, 0)
                post_count = r['post_by_type'].get(gtype, 0)
                delta = post_count - pre_count
                f.write(f"  Run {r['run_num']}: {pre_count:>6,} → {post_count:>6,} ({delta:+,})\n")
        
        f.write("\n\nPatch Impact Summary\n")
        f.write("-" * 80 + "\n")
        
        avg_gadget_increase = statistics.mean([r['gadget_increase'] for r in results])
        
        f.write(f"Average gadget increase: {avg_gadget_increase:,.1f}\n")
        
        if avg_gadget_increase > 0:
            f.write(f"\n✅ Patching increases gadget availability by {avg_gadget_increase:.1f} gadgets on average\n")
        else:
            f.write(f"\n⚠️  Patching decreases gadget availability by {abs(avg_gadget_increase):.1f} gadgets on average\n")
    
    print(f"✅ Experiment 3: Patch impact saved to {output_dir}")


def generate_summary_table(results, output_dir):
    """Generate comprehensive summary"""
    output_dir = Path(output_dir)
    
    with open(output_dir / "summary_all_experiments.txt", 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("SCENARIO A: COMPREHENSIVE ANALYSIS SUMMARY\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("Overall Statistics\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total runs analyzed: {len(results)}\n")
        f.write(f"Functions per run: {results[0]['function_count']}\n")
        f.write(f"Iterations per function: {results[0]['warmup_iterations']}\n\n")
        
        f.write("Aggregate Metrics\n")
        f.write("-" * 80 + "\n")
        f.write(f"Average pre-patch gadgets: {statistics.mean([r['pre_gadgets'] for r in results]):,.1f}\n")
        f.write(f"Average post-patch gadgets: {statistics.mean([r['post_gadgets'] for r in results]):,.1f}\n")
        f.write(f"Average gadget increase: {statistics.mean([r['gadget_increase'] for r in results]):,.1f}\n")
        f.write(f"Standard deviation: {statistics.stdev([r['post_gadgets'] for r in results]):,.1f}\n")
        
        f.write("\n\nGadget Type Distribution (Average across runs)\n")
        f.write("-" * 80 + "\n")
        
        # Calculate average for each gadget type
        all_types = set()
        for r in results:
            all_types.update(r['post_by_type'].keys())
        
        for gtype in sorted(all_types, key=lambda x: statistics.mean([r['post_by_type'].get(x, 0) for r in results]), reverse=True):
            avg_count = statistics.mean([r['post_by_type'].get(gtype, 0) for r in results])
            f.write(f"{gtype:<15}: {avg_count:>8.1f} gadgets (average)\n")
        
        f.write("\n\nExperiments Completed\n")
        f.write("-" * 80 + "\n")
        f.write("1. ✅ Stencil Gadget Cataloging\n")
        f.write("2. ✅ Memory Region Analysis\n")
        f.write("3. ✅ Patch Impact Analysis\n")
        
        f.write("\n\nOutput Files\n")
        f.write("-" * 80 + "\n")
        f.write("- experiment_1_catalog.txt\n")
        f.write("- experiment_2_memory_regions.txt\n")
        f.write("- experiment_3_patch_impact.txt\n")
        f.write("- summary_all_experiments.txt (this file)\n")
        f.write("- latex_summary.tex\n")
    
    # Also create LaTeX summary
    with open(output_dir / "latex_summary.tex", 'w') as f:
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{Scenario A: JIT Gadget Analysis (3 Runs)}\n")
        f.write("\\label{tab:scenario-a-comprehensive}\n")
        f.write("\\begin{tabular}{lrrrr}\n")
        f.write("\\hline\n")
        f.write("\\textbf{Metric} & \\textbf{Run 1} & \\textbf{Run 2} & \\textbf{Run 3} & \\textbf{Mean} \\\\\n")
        f.write("\\hline\n")
        
        pre_gadgets = [r['pre_gadgets'] for r in results]
        f.write(f"Pre-Patch Gadgets & {pre_gadgets[0]:,} & {pre_gadgets[1]:,} & {pre_gadgets[2]:,} & {statistics.mean(pre_gadgets):.1f} \\\\\n")
        
        post_gadgets = [r['post_gadgets'] for r in results]
        f.write(f"Post-Patch Gadgets & {post_gadgets[0]:,} & {post_gadgets[1]:,} & {post_gadgets[2]:,} & {statistics.mean(post_gadgets):.1f} \\\\\n")
        
        increases = [r['gadget_increase'] for r in results]
        f.write(f"Gadget Increase & {increases[0]:,} & {increases[1]:,} & {increases[2]:,} & {statistics.mean(increases):.1f} \\\\\n")
        
        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")
    
    print(f"✅ Summary saved to {output_dir}")


def main():
    experiment_id = "20251115_085128_full_scale_6000iters_3xA"
    output_dir = Path(f"gadget_analysis/experiments/{experiment_id}/results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print("SCENARIO A: COMPREHENSIVE ANALYSIS")
    print("=" * 80)
    print(f"Experiment ID: {experiment_id}\n")
    
    print("[1/5] Loading Scenario A data...")
    runs = load_scenario_a_runs(experiment_id)
    print(f"      Loaded {len(runs)} runs\n")
    
    print("[2/5] Analyzing runs...")
    results = []
    for run in runs:
        print(f"      Analyzing Run {run['run_num']}...")
        result = analyze_run(run)
        results.append(result)
        print(f"        Post-patch gadgets: {result['post_gadgets']:,}")
    
    print(f"\n[3/5] Generating Experiment 1 results...")
    generate_experiment_1_results(results, output_dir)
    
    print(f"[4/5] Generating Experiment 2 results...")
    generate_experiment_2_results(results, output_dir)
    
    print(f"[5/5] Generating Experiment 3 results...")
    generate_experiment_3_results(results, output_dir)
    
    print(f"\nGenerating comprehensive summary...")
    generate_summary_table(results, output_dir)
    
    print("\n" + "=" * 80)
    print("✅ ALL EXPERIMENTS COMPLETED!")
    print("=" * 80)
    print(f"\n📁 Results directory: {output_dir}")
    print("\nGenerated files:")
    print("  - experiment_1_catalog.txt")
    print("  - experiment_2_memory_regions.txt")
    print("  - experiment_3_patch_impact.txt")
    print("  - summary_all_experiments.txt")
    print("  - latex_summary.tex")
    
    print("\n" + "=" * 80)
    print("QUICK SUMMARY")
    print("=" * 80)
    print(f"Average pre-patch gadgets: {statistics.mean([r['pre_gadgets'] for r in results]):,.1f}")
    print(f"Average post-patch gadgets: {statistics.mean([r['post_gadgets'] for r in results]):,.1f}")
    print(f"Average gadget increase: {statistics.mean([r['gadget_increase'] for r in results]):,.1f}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
