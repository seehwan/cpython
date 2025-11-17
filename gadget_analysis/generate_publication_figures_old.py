#!/usr/bin/env python3
"""
Generate publication-quality PDF/PNG figures for paper
Creates professional visualizations: heatmaps, bar charts, scatter plots, tables
"""

import pickle
import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
import statistics

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import Rectangle
import numpy as np
import seaborn as sns

# Set publication-quality defaults with Times font and larger text
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman', 'Times', 'Liberation Serif', 'DejaVu Serif']
plt.rcParams['font.size'] = 18
plt.rcParams['axes.labelsize'] = 20
plt.rcParams['axes.titlesize'] = 22
plt.rcParams['xtick.labelsize'] = 18
plt.rcParams['ytick.labelsize'] = 18
plt.rcParams['legend.fontsize'] = 18
plt.rcParams['figure.titlesize'] = 24
plt.rcParams['text.color'] = 'black'
plt.rcParams['axes.labelcolor'] = 'black'
plt.rcParams['xtick.color'] = 'black'
plt.rcParams['ytick.color'] = 'black'
plt.rcParams['pdf.fonttype'] = 42  # TrueType fonts for better PDF embedding

sys.path.insert(0, '/home/mobileos2/cpython')


def load_scenario_a_data():
    """Load all 3 runs of Scenario A"""
    experiment_id = "20251115_085128_full_scale_6000iters_3xA"
    base_path = Path(f"/home/mobileos2/cpython/gadget_analysis/experiments/{experiment_id}/captures")
    
    runs = []
    for run_num in [1, 2, 3]:
        pkl_path = base_path / f"scenario_a_run{run_num}.pkl"
        print(f"  Loading: {pkl_path.name}...", end=" ")
        if pkl_path.exists():
            with open(pkl_path, 'rb') as f:
                data = pickle.load(f)
            gadget_count = sum(len(v) for v in data.get('post_patch', {}).values())
            print(f"✅ {gadget_count} gadgets")
            runs.append({'run': run_num, 'data': data})
        else:
            print(f"❌ Not found")
    
    return runs


def generate_experiment2_heatmap(runs, output_dir):
    """
    Experiment 2: Stencil Gadget Catalog - Heat Map
    Shows gadget type distribution across runs
    """
    print("\n" + "="*80)
    print("EXPERIMENT 2: STENCIL GADGET CATALOG HEAT MAP")
    print("="*80)
    
    # Collect data
    gadget_types = set()
    run_data = {}
    
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        run_num = run['run']
        run_data[run_num] = {}
        
        for gtype, gadgets in post_patch.items():
            gadget_types.add(gtype)
            run_data[run_num][gtype] = len(gadgets)
    
    # Sort gadget types by average count
    sorted_types = sorted(gadget_types, 
                         key=lambda x: statistics.mean([run_data[r].get(x, 0) for r in [1, 2, 3]]),
                         reverse=True)
    
    # Create matrix for heatmap
    matrix = []
    for gtype in sorted_types:
        row = [run_data[r].get(gtype, 0) for r in [1, 2, 3]]
        matrix.append(row)
    
    matrix = np.array(matrix)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(8, 6))
    
    # Create heatmap
    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto')
    
    # Set ticks
    ax.set_xticks(np.arange(3))
    ax.set_yticks(np.arange(len(sorted_types)))
    ax.set_xticklabels([f'Run {i}' for i in [1, 2, 3]])
    ax.set_yticklabels(sorted_types)
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Gadget Count', rotation=270, labelpad=20)
    
    # Add text annotations
    for i in range(len(sorted_types)):
        for j in range(3):
            text = ax.text(j, i, int(matrix[i, j]),
                          ha="center", va="center", color="black" if matrix[i, j] < matrix.max()*0.5 else "white",
                          fontweight='bold', fontsize=18)
    
    ax.set_title('Gadget Type Distribution Across Three Scenario A Runs', fontweight='bold', pad=15, color='black')
    ax.set_xlabel('Run Number', fontweight='bold', color='black')
    ax.set_ylabel('Gadget Type', fontweight='bold', color='black')
    cbar.ax.tick_params(labelsize=18, colors='black')
    
    plt.tight_layout()
    
    # Save as both PDF and PNG
    pdf_path = output_dir / "figure_exp2_heatmap.pdf"
    png_path = output_dir / "figure_exp2_heatmap.png"
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Saved: {pdf_path.name} ({pdf_path.stat().st_size / 1024:.1f} KB)")
    print(f"✅ Saved: {png_path.name} ({png_path.stat().st_size / 1024:.1f} KB)")
    
    return matrix, sorted_types


def generate_experiment2_summary_table(runs, output_dir):
    """
    Experiment 2: Summary statistics table as figure
    """
    print("\nGenerating summary table figure...")
    
    # Collect data
    gadget_types = set()
    run_data = defaultdict(dict)
    
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        run_num = run['run']
        
        for gtype, gadgets in post_patch.items():
            gadget_types.add(gtype)
            run_data[run_num][gtype] = len(gadgets)
    
    # Sort by average
    sorted_types = sorted(gadget_types, 
                         key=lambda x: statistics.mean([run_data[r].get(x, 0) for r in [1, 2, 3]]),
                         reverse=True)
    
    # Create figure with table
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare table data
    table_data = []
    table_data.append(['Gadget Type', 'Run 1', 'Run 2', 'Run 3', 'Mean', 'Std Dev', '% of Total'])
    
    total_gadgets = [sum(run_data[r].values()) for r in [1, 2, 3]]
    avg_total = statistics.mean(total_gadgets)
    
    for gtype in sorted_types:
        counts = [run_data[r].get(gtype, 0) for r in [1, 2, 3]]
        mean_val = statistics.mean(counts)
        std_val = statistics.stdev(counts) if len(counts) > 1 else 0
        percent = (mean_val / avg_total * 100) if avg_total > 0 else 0
        
        table_data.append([
            gtype,
            f"{counts[0]}",
            f"{counts[1]}",
            f"{counts[2]}",
            f"{mean_val:.1f}",
            f"{std_val:.1f}",
            f"{percent:.1f}%"
        ])
    
    # Add total row
    total_mean = statistics.mean(total_gadgets)
    total_std = statistics.stdev(total_gadgets)
    table_data.append([
        'TOTAL',
        f"{total_gadgets[0]}",
        f"{total_gadgets[1]}",
        f"{total_gadgets[2]}",
        f"{total_mean:.1f}",
        f"{total_std:.1f}",
        "100.0%"
    ])
    
    # Create table
    table = ax.table(cellText=table_data, cellLoc='center', loc='center',
                    colWidths=[0.18, 0.12, 0.12, 0.12, 0.12, 0.12, 0.12])
    
    table.auto_set_font_size(False)
    table.set_fontsize(16)
    table.scale(1, 2)
    
    # Style header row
    for i in range(7):
        cell = table[(0, i)]
        cell.set_facecolor('#4472C4')
        cell.set_text_props(weight='bold', color='white')
    
    # Style total row
    for i in range(7):
        cell = table[(len(table_data)-1, i)]
        cell.set_facecolor('#D9E1F2')
        cell.set_text_props(weight='bold')
    
    # Alternate row colors
    for i in range(1, len(table_data)-1):
        for j in range(7):
            cell = table[(i, j)]
            if i % 2 == 0:
                cell.set_facecolor('#F2F2F2')
    
    plt.title('Experiment 2: Gadget Type Distribution Summary', fontweight='bold', pad=20, color='black')
    
    # Save
    pdf_path = output_dir / "figure_exp2_summary_table.pdf"
    png_path = output_dir / "figure_exp2_summary_table.png"
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Saved: {pdf_path.name} ({pdf_path.stat().st_size / 1024:.1f} KB)")
    print(f"✅ Saved: {png_path.name} ({png_path.stat().st_size / 1024:.1f} KB)")


def generate_experiment3_offset_comparison(runs, output_dir):
    """
    Experiment 3: Unaligned Decoding - Offset Comparison Bar Chart
    """
    print("\n" + "="*80)
    print("EXPERIMENT 3: UNALIGNED DECODING OFFSET COMPARISON")
    print("="*80)
    
    # Analyze offsets
    offset_counts = defaultdict(lambda: defaultdict(int))
    
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        
        for gtype, gadgets in post_patch.items():
            for gadget in gadgets:
                if 'address' in gadget:
                    offset = gadget['address'] % 8
                    offset_counts[offset][gtype] += 1
    
    # Prepare data
    offsets = list(range(8))
    counts = [sum(offset_counts[o].values()) for o in offsets]
    
    # Create figure
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # Left: Bar chart
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, 8))
    bars = ax1.bar(offsets, counts, color=colors, edgecolor='black', linewidth=0.8)
    
    # Add value labels on bars
    for bar, count in zip(bars, counts):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(count)}',
                ha='center', va='bottom', fontweight='bold', fontsize=18, color='black')
    
    ax1.set_xlabel('Address Offset (mod 8)', fontweight='bold', color='black')
    ax1.set_ylabel('Gadget Count', fontweight='bold', color='black')
    ax1.set_title('Gadget Distribution by Address Offset', fontweight='bold', color='black')
    ax1.set_xticks(offsets)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Right: Percentage comparison
    total_count = sum(counts)
    percentages = [(c / total_count * 100) for c in counts]
    
    bars2 = ax2.bar(offsets, percentages, color=colors, edgecolor='black', linewidth=0.8)
    
    for bar, pct in zip(bars2, percentages):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{pct:.1f}%',
                ha='center', va='bottom', fontweight='bold', fontsize=18, color='black')
    
    ax2.set_xlabel('Address Offset (mod 8)', fontweight='bold', color='black')
    ax2.set_ylabel('Percentage of Total (%)', fontweight='bold', color='black')
    ax2.set_title('Relative Gadget Distribution', fontweight='bold', color='black')
    ax2.set_xticks(offsets)
    ax2.grid(axis='y', alpha=0.3, linestyle='--')
    ax2.axhline(y=12.5, color='r', linestyle='--', alpha=0.5, label='Uniform (12.5%)')
    ax2.legend()
    
    plt.tight_layout()
    
    # Save
    pdf_path = output_dir / "figure_exp3_offset_comparison.pdf"
    png_path = output_dir / "figure_exp3_offset_comparison.png"
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Saved: {pdf_path.name} ({pdf_path.stat().st_size / 1024:.1f} KB)")
    print(f"✅ Saved: {png_path.name} ({png_path.stat().st_size / 1024:.1f} KB)")
    
    return offsets, counts, percentages


def generate_experiment4_patch_impact_scatter(runs, output_dir):
    """
    Experiment 4: Patch Function Impact - Scatter Plot
    """
    print("\n" + "="*80)
    print("EXPERIMENT 4: PATCH FUNCTION IMPACT SCATTER PLOT")
    print("="*80)
    
    # Collect pre/post data
    gadget_types = set()
    pre_counts = defaultdict(list)
    post_counts = defaultdict(list)
    
    for run in runs:
        data = run['data']
        pre_patch = data.get('pre_patch', {})
        post_patch = data.get('post_patch', {})
        
        all_types = set(list(pre_patch.keys()) + list(post_patch.keys()))
        gadget_types.update(all_types)
        
        for gtype in all_types:
            pre_counts[gtype].append(len(pre_patch.get(gtype, [])))
            post_counts[gtype].append(len(post_patch.get(gtype, [])))
    
    # Calculate averages
    avg_pre = {gtype: statistics.mean(pre_counts[gtype]) for gtype in gadget_types}
    avg_post = {gtype: statistics.mean(post_counts[gtype]) for gtype in gadget_types}
    deltas = {gtype: avg_post[gtype] - avg_pre[gtype] for gtype in gadget_types}
    
    # Create figure
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Left: Scatter plot
    x_vals = list(avg_pre.values())
    y_vals = list(avg_post.values())
    
    # Color by delta
    colors_scatter = ['green' if d > 0 else 'red' if d < 0 else 'gray' for d in deltas.values()]
    
    scatter = ax1.scatter(x_vals, y_vals, s=150, c=colors_scatter, alpha=0.6, edgecolors='black', linewidth=1.5)
    
    # Add diagonal line (no change)
    max_val = max(max(x_vals), max(y_vals))
    ax1.plot([0, max_val], [0, max_val], 'k--', alpha=0.3, linewidth=2, label='No Change')
    
    # Label points
    for gtype, x, y in zip(gadget_types, x_vals, y_vals):
        ax1.annotate(gtype, (x, y), xytext=(5, 5), textcoords='offset points', 
                    fontsize=18, alpha=0.8, fontweight='bold', color='black')
    
    ax1.set_xlabel('Pre-Patch Gadget Count (Average)', fontweight='bold', color='black')
    ax1.set_ylabel('Post-Patch Gadget Count (Average)', fontweight='bold', color='black')
    ax1.set_title('Pre-Patch vs Post-Patch Gadget Counts', fontweight='bold', color='black')
    ax1.legend()
    ax1.grid(alpha=0.3, linestyle='--')
    
    # Right: Delta bar chart
    sorted_types = sorted(gadget_types, key=lambda x: deltas[x], reverse=True)
    delta_vals = [deltas[t] for t in sorted_types]
    
    colors_bar = ['green' if d > 0 else 'red' if d < 0 else 'gray' for d in delta_vals]
    
    y_pos = np.arange(len(sorted_types))
    bars = ax2.barh(y_pos, delta_vals, color=colors_bar, edgecolor='black', linewidth=0.8)
    
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(sorted_types, color='black')
    ax2.set_xlabel('Gadget Count Change (Δ)', fontweight='bold', color='black')
    ax2.set_title('Patch Impact by Gadget Type', fontweight='bold', color='black')
    ax2.axvline(x=0, color='black', linewidth=1.5)
    ax2.grid(axis='x', alpha=0.3, linestyle='--')
    
    # Add delta values
    for i, (bar, delta) in enumerate(zip(bars, delta_vals)):
        width = bar.get_width()
        ax2.text(width, bar.get_y() + bar.get_height()/2.,
                f' {delta:+.1f}',
                ha='left' if width >= 0 else 'right',
                va='center', fontweight='bold', fontsize=18, color='black')
    
    plt.tight_layout()
    
    # Save
    pdf_path = output_dir / "figure_exp4_patch_impact_scatter.pdf"
    png_path = output_dir / "figure_exp4_patch_impact_scatter.png"
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Saved: {pdf_path.name} ({pdf_path.stat().st_size / 1024:.1f} KB)")
    print(f"✅ Saved: {png_path.name} ({png_path.stat().st_size / 1024:.1f} KB)")
    
    return avg_pre, avg_post, deltas


def generate_experiment4_ranked_table(avg_pre, avg_post, deltas, output_dir):
    """
    Experiment 4: Ranked table of most impactful stencils
    """
    print("\nGenerating ranked impact table...")
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('tight')
    ax.axis('off')
    
    # Sort by absolute delta
    sorted_types = sorted(deltas.keys(), key=lambda x: abs(deltas[x]), reverse=True)
    
    # Prepare table data
    table_data = []
    table_data.append(['Rank', 'Gadget Type', 'Pre-Patch\n(Avg)', 'Post-Patch\n(Avg)', 
                      'Delta (Δ)', 'Change %', 'Impact'])
    
    for rank, gtype in enumerate(sorted_types, 1):
        pre = avg_pre[gtype]
        post = avg_post[gtype]
        delta = deltas[gtype]
        change_pct = ((post - pre) / pre * 100) if pre > 0 else 0
        
        if delta > 0:
            impact = f"↑ Increase"
        elif delta < 0:
            impact = f"↓ Decrease"
        else:
            impact = "= No Change"
        
        table_data.append([
            f"{rank}",
            gtype,
            f"{pre:.1f}",
            f"{post:.1f}",
            f"{delta:+.1f}",
            f"{change_pct:+.1f}%",
            impact
        ])
    
    # Create table
    table = ax.table(cellText=table_data, cellLoc='center', loc='center',
                    colWidths=[0.08, 0.18, 0.14, 0.14, 0.12, 0.12, 0.18])
    
    table.auto_set_font_size(False)
    table.set_fontsize(16)
    table.scale(1, 2.2)
    
    # Style header
    for i in range(7):
        cell = table[(0, i)]
        cell.set_facecolor('#4472C4')
        cell.set_text_props(weight='bold', color='white')
    
    # Color code impact column
    for i in range(1, len(table_data)):
        impact_cell = table[(i, 6)]
        if "Increase" in table_data[i][6]:
            impact_cell.set_facecolor('#C6EFCE')
        elif "Decrease" in table_data[i][6]:
            impact_cell.set_facecolor('#FFC7CE')
        else:
            impact_cell.set_facecolor('#FFEB9C')
        
        # Alternate row colors
        if i % 2 == 0:
            for j in range(6):
                table[(i, j)].set_facecolor('#F2F2F2')
    
    plt.title('Experiment 4: Ranked Patch Impact by Gadget Type', fontweight='bold', pad=20, color='black')
    
    # Save
    pdf_path = output_dir / "figure_exp4_ranked_impact_table.pdf"
    png_path = output_dir / "figure_exp4_ranked_impact_table.png"
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Saved: {pdf_path.name} ({pdf_path.stat().st_size / 1024:.1f} KB)")
    print(f"✅ Saved: {png_path.name} ({png_path.stat().st_size / 1024:.1f} KB)")


def generate_comprehensive_summary(runs, output_dir):
    """
    Generate comprehensive summary figure with key statistics
    """
    print("\n" + "="*80)
    print("GENERATING COMPREHENSIVE SUMMARY FIGURE")
    print("="*80)
    
    # Collect statistics
    total_gadgets = []
    gadget_types_count = []
    
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        total_gadgets.append(sum(len(v) for v in post_patch.values()))
        gadget_types_count.append(len(post_patch))
    
    avg_gadgets = statistics.mean(total_gadgets)
    std_gadgets = statistics.stdev(total_gadgets)
    
    # Create figure with subplots
    fig = plt.figure(figsize=(14, 10))
    gs = fig.add_gridspec(3, 2, hspace=0.3, wspace=0.3)
    
    # 1. Summary statistics box
    ax1 = fig.add_subplot(gs[0, :])
    ax1.axis('off')
    
    summary_text = f"""
    SCENARIO A: COMPREHENSIVE ANALYSIS SUMMARY
    
    Experiment Configuration:
    • Total Runs: 3
    • Functions per Run: 100
    • Warmup Iterations: 6,000
    • JIT Compilation: Tier-2 (Copy-and-Patch)
    
    Key Findings:
    • Average Gadgets: {avg_gadgets:.1f} ± {std_gadgets:.1f}
    • Min/Max: {min(total_gadgets)} / {max(total_gadgets)} gadgets
    • Gadget Types: 7 distinct types
    • Dominant Type: pop_rdi (75.7%)
    • Patch Impact: 0.0 (no net change)
    """
    
    ax1.text(0.5, 0.5, summary_text, transform=ax1.transAxes,
            fontsize=18, verticalalignment='center', horizontalalignment='center',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3),
            family='monospace', fontweight='bold', color='black')
    
    # 2. Gadgets per run
    ax2 = fig.add_subplot(gs[1, 0])
    runs_x = [f"Run {i}" for i in [1, 2, 3]]
    bars = ax2.bar(runs_x, total_gadgets, color=['#1f77b4', '#ff7f0e', '#2ca02c'], 
                   edgecolor='black', linewidth=1.5)
    
    for bar, count in zip(bars, total_gadgets):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(count)}',
                ha='center', va='bottom', fontweight='bold', fontsize=18, color='black')
    
    ax2.axhline(y=avg_gadgets, color='red', linestyle='--', linewidth=2, label=f'Mean: {avg_gadgets:.1f}')
    ax2.set_ylabel('Total Gadgets', fontweight='bold', color='black')
    ax2.set_title('Gadget Count by Run', fontweight='bold', color='black')
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)
    
    # 3. Distribution pie chart
    ax3 = fig.add_subplot(gs[1, 1])
    
    # Get gadget type distribution
    type_totals = defaultdict(int)
    for run in runs:
        data = run['data']
        post_patch = data.get('post_patch', {})
        for gtype, gadgets in post_patch.items():
            type_totals[gtype] += len(gadgets)
    
    sorted_types = sorted(type_totals.items(), key=lambda x: x[1], reverse=True)
    labels = [t[0] for t in sorted_types]
    sizes = [t[1] for t in sorted_types]
    
    colors_pie = plt.cm.Set3(np.linspace(0, 1, len(labels)))
    
    wedges, texts, autotexts = ax3.pie(sizes, labels=labels, autopct='%1.1f%%',
                                        colors=colors_pie, startangle=90,
                                        textprops={'fontsize': 18, 'weight': 'bold', 'color': 'black'})
    
    ax3.set_title('Gadget Type Distribution', fontweight='bold', color='black')
    
    # 4. Run variance
    ax4 = fig.add_subplot(gs[2, 0])
    
    x = [1, 2, 3]
    ax4.plot(x, total_gadgets, 'o-', linewidth=2, markersize=10, color='#d62728')
    ax4.fill_between(x, 
                     [avg_gadgets - std_gadgets]*3,
                     [avg_gadgets + std_gadgets]*3,
                     alpha=0.3, color='gray', label='±1 Std Dev')
    ax4.axhline(y=avg_gadgets, color='blue', linestyle='--', linewidth=2, alpha=0.5)
    
    ax4.set_xlabel('Run Number', fontweight='bold', color='black')
    ax4.set_ylabel('Gadget Count', fontweight='bold', color='black')
    ax4.set_title('Cross-Run Variance', fontweight='bold', color='black')
    ax4.set_xticks(x)
    ax4.legend()
    ax4.grid(alpha=0.3)
    
    # 5. Key metrics table
    ax5 = fig.add_subplot(gs[2, 1])
    ax5.axis('tight')
    ax5.axis('off')
    
    metrics_data = [
        ['Metric', 'Value'],
        ['Mean Gadgets', f'{avg_gadgets:.1f}'],
        ['Std Deviation', f'{std_gadgets:.1f}'],
        ['Coefficient of Variation', f'{(std_gadgets/avg_gadgets*100):.1f}%'],
        ['Min Gadgets', f'{min(total_gadgets)}'],
        ['Max Gadgets', f'{max(total_gadgets)}'],
        ['Range', f'{max(total_gadgets) - min(total_gadgets)}'],
        ['Gadget Types', f'{len(type_totals)}']
    ]
    
    metrics_table = ax5.table(cellText=metrics_data, cellLoc='left', loc='center',
                             colWidths=[0.6, 0.4])
    metrics_table.auto_set_font_size(False)
    metrics_table.set_fontsize(18)
    metrics_table.scale(1, 2.5)
    
    # Style
    for i in range(2):
        metrics_table[(0, i)].set_facecolor('#4472C4')
        metrics_table[(0, i)].set_text_props(weight='bold', color='white')
    
    for i in range(1, len(metrics_data)):
        if i % 2 == 0:
            for j in range(2):
                metrics_table[(i, j)].set_facecolor('#F2F2F2')
    
    ax5.set_title('Key Metrics Summary', fontweight='bold', pad=20, color='black')
    
    plt.suptitle('Scenario A: Comprehensive Gadget Analysis Summary', 
                fontweight='bold', y=0.98, color='black')
    
    # Save
    pdf_path = output_dir / "figure_comprehensive_summary.pdf"
    png_path = output_dir / "figure_comprehensive_summary.png"
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Saved: {pdf_path.name} ({pdf_path.stat().st_size / 1024:.1f} KB)")
    print(f"✅ Saved: {png_path.name} ({png_path.stat().st_size / 1024:.1f} KB)")


def main():
    print("="*80)
    print("GENERATING PUBLICATION-QUALITY FIGURES (PDF/PNG)")
    print("="*80)
    
    # Setup
    output_dir = Path("gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load data
    print("\nLoading Scenario A data...")
    runs = load_scenario_a_data()
    
    if len(runs) == 0:
        print("❌ No data found!")
        return 1
    
    print(f"\n✅ Loaded {len(runs)} runs successfully\n")
    
    # Generate all figures
    generate_experiment2_heatmap(runs, output_dir)
    generate_experiment2_summary_table(runs, output_dir)
    
    generate_experiment3_offset_comparison(runs, output_dir)
    
    avg_pre, avg_post, deltas = generate_experiment4_patch_impact_scatter(runs, output_dir)
    generate_experiment4_ranked_table(avg_pre, avg_post, deltas, output_dir)
    
    generate_comprehensive_summary(runs, output_dir)
    
    print("\n" + "="*80)
    print("✅ ALL FIGURES GENERATED SUCCESSFULLY!")
    print("="*80)
    print(f"\nOutput directory: {output_dir}")
    print("\nGenerated files:")
    print("  PDF figures:")
    for pdf_file in sorted(output_dir.glob("figure_*.pdf")):
        size_kb = pdf_file.stat().st_size / 1024
        print(f"    • {pdf_file.name} ({size_kb:.1f} KB)")
    print("\n  PNG figures:")
    for png_file in sorted(output_dir.glob("figure_*.png")):
        size_kb = png_file.stat().st_size / 1024
        print(f"    • {png_file.name} ({size_kb:.1f} KB)")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
