#!/usr/bin/env python3
"""
Generate publication-quality figures and tables for paper
Uses only standard library (no matplotlib) - generates ASCII/LaTeX outputs
"""

import pickle
import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
import statistics

sys.path.insert(0, '/home/mobileos2/cpython')


def load_scenario_a_data():
    """Load all 3 runs of Scenario A"""
    experiment_id = "20251115_085128_full_scale_6000iters_3xA"
    base_path = Path(f"/home/mobileos2/cpython/gadget_analysis/experiments/{experiment_id}/captures")
    
    runs = []
    for run_num in [1, 2, 3]:
        pkl_path = base_path / f"scenario_a_run{run_num}.pkl"
        print(f"  Checking: {pkl_path}")
        if pkl_path.exists():
            with open(pkl_path, 'rb') as f:
                data = pickle.load(f)
            print(f"  ✅ Loaded run {run_num}: {sum(len(v) for v in data.get('post_patch', {}).values())} gadgets")
            runs.append({'run': run_num, 'data': data})
        else:
            print(f"  ❌ Not found: {pkl_path}")
    
    return runs


def generate_experiment2_heatmap_data(runs):
    """
    Experiment 2: Stencil Gadget Catalog
    Generate heat map data showing gadget types per stencil
    """
    print("\n" + "="*80)
    print("EXPERIMENT 2: STENCIL GADGET CATALOG")
    print("="*80)
    
    # Aggregate gadgets by type across all runs
    all_gadget_types = set()
    gadget_counts = defaultdict(lambda: defaultdict(int))
    
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        run_num = run['run']
        
        for gtype, gadgets in post_patch.items():
            all_gadget_types.add(gtype)
            gadget_counts[run_num][gtype] = len(gadgets)
    
    # Calculate averages
    avg_counts = {}
    for gtype in all_gadget_types:
        counts = [gadget_counts[r][gtype] for r in [1, 2, 3] if gtype in gadget_counts[r]]
        avg_counts[gtype] = statistics.mean(counts) if counts else 0
    
    if not avg_counts:
        print("❌ No gadget data found")
        return {}
    
    # Generate LaTeX table
    output_dir = Path("gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "table_experiment2_catalog.tex", 'w') as f:
        f.write("% Experiment 2: Stencil Gadget Catalog\n")
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{Gadget Type Distribution Across Three Scenario A Runs}\n")
        f.write("\\label{tab:experiment2-catalog}\n")
        f.write("\\begin{tabular}{lrrrr}\n")
        f.write("\\toprule\n")
        f.write("\\textbf{Gadget Type} & \\textbf{Run 1} & \\textbf{Run 2} & \\textbf{Run 3} & \\textbf{Mean} \\\\\n")
        f.write("\\midrule\n")
        
        # Sort by average count (descending)
        sorted_types = sorted(all_gadget_types, 
                            key=lambda x: avg_counts.get(x, 0), 
                            reverse=True)
        
        for gtype in sorted_types:
            r1 = gadget_counts[1].get(gtype, 0)
            r2 = gadget_counts[2].get(gtype, 0)
            r3 = gadget_counts[3].get(gtype, 0)
            avg = avg_counts.get(gtype, 0)
            f.write(f"\\texttt{{{gtype}}} & {r1} & {r2} & {r3} & {avg:.1f} \\\\\n")
        
        # Add totals
        f.write("\\midrule\n")
        total_r1 = sum(gadget_counts[1].values())
        total_r2 = sum(gadget_counts[2].values())
        total_r3 = sum(gadget_counts[3].values())
        total_avg = statistics.mean([total_r1, total_r2, total_r3])
        f.write(f"\\textbf{{Total}} & {total_r1} & {total_r2} & {total_r3} & {total_avg:.1f} \\\\\n")
        
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")
    
    # Generate ASCII heat map
    with open(output_dir / "figure_experiment2_heatmap.txt", 'w') as f:
        f.write("Gadget Type Heat Map (Scenario A - Average Across 3 Runs)\n")
        f.write("="*80 + "\n\n")
        
        max_count = max(avg_counts.values())
        for gtype in sorted_types:
            count = avg_counts.get(gtype, 0)
            bar_length = int((count / max_count) * 50) if max_count > 0 else 0
            bar = '█' * bar_length
            percent = (count / sum(avg_counts.values()) * 100) if sum(avg_counts.values()) > 0 else 0
            f.write(f"{gtype:12} {bar:50} {count:6.1f} ({percent:5.1f}%)\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write(f"Total Gadgets (Average): {sum(avg_counts.values()):.1f}\n")
    
    print(f"✅ Generated: table_experiment2_catalog.tex")
    print(f"✅ Generated: figure_experiment2_heatmap.txt")
    
    return avg_counts


def generate_experiment3_offset_analysis(runs):
    """
    Experiment 3: Unaligned Decoding
    Simulate offset analysis by examining gadget addresses
    """
    print("\n" + "="*80)
    print("EXPERIMENT 3: UNALIGNED DECODING ANALYSIS")
    print("="*80)
    
    output_dir = Path("gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results")
    
    # Analyze gadget address alignments
    offset_gadgets = defaultdict(lambda: defaultdict(int))
    
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        
        for gtype, gadgets in post_patch.items():
            for gadget in gadgets:
                if 'address' in gadget:
                    # Calculate offset within 8-byte boundary
                    offset = gadget['address'] % 8
                    offset_gadgets[offset][gtype] += 1
    
    # Generate LaTeX table
    with open(output_dir / "table_experiment3_offsets.tex", 'w') as f:
        f.write("% Experiment 3: Unaligned Decoding Analysis\n")
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{Gadget Distribution by Address Offset (0--7)}\n")
        f.write("\\label{tab:experiment3-offsets}\n")
        f.write("\\begin{tabular}{crrr}\n")
        f.write("\\toprule\n")
        f.write("\\textbf{Offset} & \\textbf{Gadgets} & \\textbf{\\% of Total} & \\textbf{Density} \\\\\n")
        f.write("\\midrule\n")
        
        total_gadgets = sum(sum(types.values()) for types in offset_gadgets.values())
        
        for offset in range(8):
            count = sum(offset_gadgets[offset].values())
            percent = (count / total_gadgets * 100) if total_gadgets > 0 else 0
            density = count / 3  # Average per run
            f.write(f"{offset} & {count} & {percent:.1f}\\% & {density:.1f} \\\\\n")
        
        f.write("\\midrule\n")
        f.write(f"\\textbf{{Total}} & {total_gadgets} & 100.0\\% & {total_gadgets/3:.1f} \\\\\n")
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")
    
    # Generate ASCII bar chart
    with open(output_dir / "figure_experiment3_offsets.txt", 'w') as f:
        f.write("Gadget Distribution by Address Offset\n")
        f.write("="*80 + "\n\n")
        f.write("Offset  Count    Bar Chart\n")
        f.write("-"*80 + "\n")
        
        max_count = max((sum(offset_gadgets[o].values()) for o in range(8)), default=1)
        
        for offset in range(8):
            count = sum(offset_gadgets[offset].values())
            bar_length = int((count / max_count) * 40) if max_count > 0 else 0
            bar = '█' * bar_length
            percent = (count / total_gadgets * 100) if total_gadgets > 0 else 0
            f.write(f"  {offset}     {count:5}    {bar:40} {percent:5.1f}%\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write(f"Total Gadgets: {total_gadgets}\n")
        f.write(f"Most common offsets: {sorted(range(8), key=lambda x: sum(offset_gadgets[x].values()), reverse=True)[:3]}\n")
    
    print(f"✅ Generated: table_experiment3_offsets.tex")
    print(f"✅ Generated: figure_experiment3_offsets.txt")
    
    return offset_gadgets


def generate_experiment4_patch_impact(runs):
    """
    Experiment 4: Patch Function Impact
    Analyze pre-patch vs post-patch changes
    """
    print("\n" + "="*80)
    print("EXPERIMENT 4: PATCH FUNCTION IMPACT")
    print("="*80)
    
    output_dir = Path("gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results")
    
    # Calculate deltas
    patch_impacts = []
    
    for run in runs:
        data = run['data']
        pre_patch = data.get('pre_patch', {})
        post_patch = data.get('post_patch', {})
        
        for gtype in set(list(pre_patch.keys()) + list(post_patch.keys())):
            pre_count = len(pre_patch.get(gtype, []))
            post_count = len(post_patch.get(gtype, []))
            delta = post_count - pre_count
            
            patch_impacts.append({
                'run': run['run'],
                'type': gtype,
                'pre': pre_count,
                'post': post_count,
                'delta': delta
            })
    
    # Generate LaTeX table
    with open(output_dir / "table_experiment4_impact.tex", 'w') as f:
        f.write("% Experiment 4: Patch Function Impact\n")
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{Gadget Count Changes: Pre-Patch vs Post-Patch}\n")
        f.write("\\label{tab:experiment4-impact}\n")
        f.write("\\begin{tabular}{lrrrc}\n")
        f.write("\\toprule\n")
        f.write("\\textbf{Gadget Type} & \\textbf{Pre-Patch} & \\textbf{Post-Patch} & \\textbf{$\\Delta$} & \\textbf{Change} \\\\\n")
        f.write("\\midrule\n")
        
        # Aggregate by type
        type_impacts = defaultdict(lambda: {'pre': [], 'post': [], 'delta': []})
        for impact in patch_impacts:
            type_impacts[impact['type']]['pre'].append(impact['pre'])
            type_impacts[impact['type']]['post'].append(impact['post'])
            type_impacts[impact['type']]['delta'].append(impact['delta'])
        
        for gtype, values in sorted(type_impacts.items()):
            avg_pre = statistics.mean(values['pre'])
            avg_post = statistics.mean(values['post'])
            avg_delta = statistics.mean(values['delta'])
            
            if avg_delta > 0:
                change = f"+{avg_delta:.1f}"
            elif avg_delta < 0:
                change = f"{avg_delta:.1f}"
            else:
                change = "0.0"
            
            f.write(f"\\texttt{{{gtype}}} & {avg_pre:.1f} & {avg_post:.1f} & {avg_delta:+.1f} & {change} \\\\\n")
        
        f.write("\\midrule\n")
        total_pre = statistics.mean([sum(v['pre']) for v in type_impacts.values()])
        total_post = statistics.mean([sum(v['post']) for v in type_impacts.values()])
        total_delta = total_post - total_pre
        f.write(f"\\textbf{{Total}} & {total_pre:.1f} & {total_post:.1f} & {total_delta:+.1f} & {total_delta:+.1f} \\\\\n")
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")
    
    # Generate scatter plot data (ASCII)
    with open(output_dir / "figure_experiment4_scatter.txt", 'w') as f:
        f.write("Patch Impact Scatter Plot\n")
        f.write("="*80 + "\n\n")
        f.write("Gadget Type    Pre-Patch  Post-Patch  Delta   Visual Impact\n")
        f.write("-"*80 + "\n")
        
        for gtype, values in sorted(type_impacts.items(), 
                                   key=lambda x: statistics.mean(x[1]['delta']), 
                                   reverse=True):
            avg_pre = statistics.mean(values['pre'])
            avg_post = statistics.mean(values['post'])
            avg_delta = statistics.mean(values['delta'])
            
            # Visual representation
            if avg_delta > 0:
                visual = "+" * min(int(abs(avg_delta) / 10), 20)
            elif avg_delta < 0:
                visual = "-" * min(int(abs(avg_delta) / 10), 20)
            else:
                visual = "="
            
            f.write(f"{gtype:12}  {avg_pre:8.1f}  {avg_post:9.1f}  {avg_delta:+6.1f}   {visual}\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("Key: + (increase), - (decrease), = (no change)\n")
    
    print(f"✅ Generated: table_experiment4_impact.tex")
    print(f"✅ Generated: figure_experiment4_scatter.txt")
    
    return patch_impacts


def generate_summary_statistics(runs, gadget_catalog, offset_data, patch_impacts):
    """Generate comprehensive summary statistics"""
    print("\n" + "="*80)
    print("GENERATING SUMMARY STATISTICS")
    print("="*80)
    
    output_dir = Path("gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results")
    
    with open(output_dir / "paper_statistics_summary.txt", 'w') as f:
        f.write("="*80 + "\n")
        f.write("COMPREHENSIVE STATISTICS FOR PAPER\n")
        f.write("="*80 + "\n\n")
        
        # Overall statistics
        f.write("OVERALL STATISTICS\n")
        f.write("-"*80 + "\n")
        f.write(f"Total Runs: 3\n")
        f.write(f"Functions per Run: 100\n")
        f.write(f"Warmup Iterations: 6,000\n\n")
        
        # Gadget statistics
        total_gadgets = [sum(len(run['data'].get('post_patch', {}).get(t, [])) 
                            for t in run['data'].get('post_patch', {}).keys()) 
                        for run in runs]
        
        f.write("GADGET STATISTICS\n")
        f.write("-"*80 + "\n")
        f.write(f"Average Gadgets per Run: {statistics.mean(total_gadgets):.1f}\n")
        f.write(f"Standard Deviation: {statistics.stdev(total_gadgets):.1f}\n")
        f.write(f"Min Gadgets: {min(total_gadgets)}\n")
        f.write(f"Max Gadgets: {max(total_gadgets)}\n")
        f.write(f"Range: {max(total_gadgets) - min(total_gadgets)}\n\n")
        
        # Type distribution
        f.write("GADGET TYPE DISTRIBUTION\n")
        f.write("-"*80 + "\n")
        for gtype, count in sorted(gadget_catalog.items(), key=lambda x: x[1], reverse=True):
            percent = (count / sum(gadget_catalog.values()) * 100)
            f.write(f"{gtype:12}: {count:6.1f} ({percent:5.1f}%)\n")
        
        f.write("\n")
        f.write("="*80 + "\n")
    
    print(f"✅ Generated: paper_statistics_summary.txt")


def main():
    print("="*80)
    print("GENERATING PAPER FIGURES AND TABLES")
    print("="*80)
    
    # Load data
    print("\nLoading Scenario A data...")
    runs = load_scenario_a_data()
    print(f"Loaded {len(runs)} runs\n")
    
    # Generate all figures and tables
    gadget_catalog = generate_experiment2_heatmap_data(runs)
    offset_data = generate_experiment3_offset_analysis(runs)
    patch_impacts = generate_experiment4_patch_impact(runs)
    generate_summary_statistics(runs, gadget_catalog, offset_data, patch_impacts)
    
    print("\n" + "="*80)
    print("✅ ALL FIGURES AND TABLES GENERATED!")
    print("="*80)
    print("\nOutput location: gadget_analysis/experiments/.../results/")
    print("\nGenerated files:")
    print("  - table_experiment2_catalog.tex")
    print("  - figure_experiment2_heatmap.txt")
    print("  - table_experiment3_offsets.tex")
    print("  - figure_experiment3_offsets.txt")
    print("  - table_experiment4_impact.tex")
    print("  - figure_experiment4_scatter.txt")
    print("  - paper_statistics_summary.txt")
    print("\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
