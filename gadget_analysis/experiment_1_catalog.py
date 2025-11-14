#!/usr/bin/env python3
"""
Experiment 1: Stencil Gadget Cataloging
========================================

Systematically scan all JIT stencils and generate:
1. Comprehensive gadget catalog (JSON)
2. Heat map visualization (stencil × gadget category)
3. Statistical summary report

Usage:
    python experiment_1_catalog.py
"""

import sys
import os
import json
from pathlib import Path
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import seaborn as sns
import numpy as np
from datetime import datetime

# Add cpython to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gadget_analysis import scanner, generator, classifier

# Configuration
OUTPUT_DIR = Path(__file__).parent / "experiment_1_results"
CATALOG_FILE = OUTPUT_DIR / "stencil_gadget_catalog.json"
HEATMAP_FILE = OUTPUT_DIR / "heatmap_stencil_gadget_categories.png"
SUMMARY_FILE = OUTPUT_DIR / "summary_statistics.txt"


def setup_output_directory():
    """Create output directory if it doesn't exist"""
    OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"[*] Output directory: {OUTPUT_DIR}")


def generate_test_functions():
    """Generate test functions and collect stencil information"""
    print("[*] Generating test functions...")
    
    gen = generator.JITFunctionGenerator(use_optimizer=True)
    
    # Generate 100 functions for analysis
    functions = gen.generate(count=100)
    
    # Trigger JIT compilation
    print("[*] Triggering JIT compilation...")
    gen.warmup()
    
    print(f"[+] Generated and warmed up {len(functions)} functions")
    print(f"[+] JIT compiled: {gen.stats['jit_compiled']}")
    
    return gen


def scan_jit_memory():
    """Scan JIT memory for gadgets"""
    print("[*] Scanning JIT memory for gadgets...")
    
    jit_scanner = scanner.RuntimeJITScanner()
    
    # Import the jitexecleak module to access functions
    try:
        from gadget_analysis import jitexecleak
        
        # Get all executable functions
        func_count = 0
        for name in dir(jitexecleak):
            obj = getattr(jitexecleak, name)
            if callable(obj) and not name.startswith('_'):
                try:
                    jit_scanner.scan_function_memory(obj)
                    func_count += 1
                except Exception as e:
                    pass
        
        print(f"[+] Scanned {func_count} functions")
        
    except ImportError:
        print("[!] jitexecleak module not available, using generated functions")
    
    # Get scan results
    results = jit_scanner.get_results()
    
    print(f"[+] Total gadgets found: {results['total_gadgets']}")
    print(f"[+] Total bytes scanned: {results['total_bytes_scanned']}")
    
    return results


def classify_gadgets(results):
    """Classify all gadgets by category"""
    print("[*] Classifying gadgets...")
    
    gc = classifier.GadgetClassifier()
    
    # Classify each gadget
    classified = defaultdict(lambda: defaultdict(list))
    
    for category, gadget_list in results['gadgets'].items():
        for gadget in gadget_list:
            # Get the instruction string
            insn_str = gadget.get('instructions', '')
            
            # Classify
            gadget_type = gc.classify_gadget(insn_str)
            
            # Store with stencil info (use category as proxy for stencil)
            classified[category][gadget_type].append(gadget)
    
    print(f"[+] Classified {sum(len(v) for cat in classified.values() for v in cat.values())} gadgets")
    
    return classified


def create_catalog(classified_gadgets, results):
    """Create comprehensive gadget catalog"""
    print("[*] Creating gadget catalog...")
    
    catalog = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'total_gadgets': results['total_gadgets'],
            'total_bytes_scanned': results['total_bytes_scanned'],
            'functions_scanned': results['functions_scanned'],
            'scan_time': results['scan_time'],
        },
        'stencils': {},
        'statistics': {
            'by_category': {},
            'by_type': defaultdict(int),
        }
    }
    
    # Process each stencil (category)
    for stencil_name, type_dict in classified_gadgets.items():
        stencil_data = {
            'gadget_count': sum(len(gadgets) for gadgets in type_dict.values()),
            'types': {}
        }
        
        for gadget_type, gadgets in type_dict.items():
            stencil_data['types'][gadget_type] = {
                'count': len(gadgets),
                'examples': [
                    {
                        'address': g.get('address', 0),
                        'instructions': g.get('instructions', ''),
                        'bytes': g.get('bytes', ''),
                    }
                    for g in gadgets[:3]  # Store only first 3 examples
                ]
            }
            
            # Update statistics
            catalog['statistics']['by_type'][gadget_type] += len(gadgets)
        
        catalog['stencils'][stencil_name] = stencil_data
        catalog['statistics']['by_category'][stencil_name] = stencil_data['gadget_count']
    
    # Save catalog
    with open(CATALOG_FILE, 'w') as f:
        json.dump(catalog, f, indent=2, default=str)
    
    print(f"[+] Catalog saved to {CATALOG_FILE}")
    
    return catalog


def create_heatmap(classified_gadgets):
    """Create heat map: stencil × gadget category"""
    print("[*] Creating heat map visualization...")
    
    # Get all stencil names and gadget types
    stencil_names = sorted(classified_gadgets.keys())
    gadget_types = sorted(set(
        gtype 
        for type_dict in classified_gadgets.values() 
        for gtype in type_dict.keys()
    ))
    
    # Create matrix
    matrix = np.zeros((len(stencil_names), len(gadget_types)))
    
    for i, stencil in enumerate(stencil_names):
        for j, gtype in enumerate(gadget_types):
            matrix[i, j] = len(classified_gadgets[stencil].get(gtype, []))
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, max(8, len(stencil_names) * 0.4)))
    
    # Create heatmap
    sns.heatmap(
        matrix,
        xticklabels=gadget_types,
        yticklabels=stencil_names,
        cmap='YlOrRd',
        annot=True,
        fmt='.0f',
        cbar_kws={'label': 'Gadget Count'},
        ax=ax
    )
    
    ax.set_title('Gadget Distribution: Stencil × Gadget Category', fontsize=16, pad=20)
    ax.set_xlabel('Gadget Category', fontsize=12)
    ax.set_ylabel('Stencil (Opcode Category)', fontsize=12)
    
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    
    # Save figure
    plt.savefig(HEATMAP_FILE, dpi=300, bbox_inches='tight')
    print(f"[+] Heat map saved to {HEATMAP_FILE}")
    
    plt.close()


def generate_summary(catalog):
    """Generate summary statistics report"""
    print("[*] Generating summary report...")
    
    with open(SUMMARY_FILE, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("EXPERIMENT 1: STENCIL GADGET CATALOG - SUMMARY STATISTICS\n")
        f.write("=" * 80 + "\n\n")
        
        # Metadata
        f.write("Scan Metadata:\n")
        f.write("-" * 80 + "\n")
        metadata = catalog['metadata']
        f.write(f"  Timestamp:           {metadata['timestamp']}\n")
        f.write(f"  Functions Scanned:   {metadata['functions_scanned']}\n")
        f.write(f"  Total Bytes Scanned: {metadata['total_bytes_scanned']:,} bytes\n")
        f.write(f"  Scan Time:           {metadata['scan_time']:.3f} seconds\n")
        f.write(f"  Total Gadgets:       {metadata['total_gadgets']}\n")
        f.write("\n")
        
        # Top stencils by gadget count
        f.write("Top 10 Stencils by Gadget Count:\n")
        f.write("-" * 80 + "\n")
        top_stencils = sorted(
            catalog['statistics']['by_category'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        for rank, (stencil, count) in enumerate(top_stencils, 1):
            f.write(f"  {rank:2d}. {stencil:30s} {count:4d} gadgets\n")
        f.write("\n")
        
        # Gadget type distribution
        f.write("Gadget Type Distribution:\n")
        f.write("-" * 80 + "\n")
        type_stats = sorted(
            catalog['statistics']['by_type'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        total = sum(count for _, count in type_stats)
        for gtype, count in type_stats:
            percentage = (count / total * 100) if total > 0 else 0
            f.write(f"  {gtype:30s} {count:4d} ({percentage:5.1f}%)\n")
        f.write("\n")
        
        # Gadget density analysis
        f.write("Gadget Density Analysis:\n")
        f.write("-" * 80 + "\n")
        if metadata['total_bytes_scanned'] > 0:
            density = metadata['total_gadgets'] / metadata['total_bytes_scanned'] * 100
            f.write(f"  Overall Density: {density:.2f} gadgets per 100 bytes\n")
        
        # Per-stencil density (if available)
        f.write("\n  Per-Stencil Density (Top 10):\n")
        for stencil, count in top_stencils:
            # Estimate: assume average stencil is ~100 bytes
            est_density = count / 1.0  # gadgets per estimated 100 bytes
            f.write(f"    {stencil:30s} ~{est_density:.1f} gadgets/100 bytes\n")
        
        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")
    
    print(f"[+] Summary report saved to {SUMMARY_FILE}")


def main():
    """Main experiment runner"""
    print("\n" + "=" * 80)
    print("EXPERIMENT 1: STENCIL GADGET CATALOGING")
    print("=" * 80 + "\n")
    
    # Setup
    setup_output_directory()
    
    # Step 1: Generate test functions
    gen = generate_test_functions()
    
    # Step 2: Scan JIT memory
    results = scan_jit_memory()
    
    # Step 3: Classify gadgets
    classified = classify_gadgets(results)
    
    # Step 4: Create catalog
    catalog = create_catalog(classified, results)
    
    # Step 5: Create heat map
    create_heatmap(classified)
    
    # Step 6: Generate summary
    generate_summary(catalog)
    
    print("\n" + "=" * 80)
    print("EXPERIMENT 1 COMPLETE")
    print("=" * 80)
    print(f"\nResults saved to: {OUTPUT_DIR}")
    print(f"  - Catalog:  {CATALOG_FILE.name}")
    print(f"  - Heat Map: {HEATMAP_FILE.name}")
    print(f"  - Summary:  {SUMMARY_FILE.name}")
    print()


if __name__ == '__main__':
    main()
