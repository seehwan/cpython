#!/usr/bin/env python3
"""
Stencil Optimization Comparison Test
=====================================

Compares standard function generation vs optimized generation.

Usage:
    python3 test_stencil_optimization.py -n 10
"""

import argparse
import sys
import os

# Add gadget_analysis directory to path
sys.path.insert(0, '/home/mobileos2')

from gadget_analysis import (
    JITFunctionGenerator,
    RuntimeJITScanner,
    GadgetReporter,
    StencilOptimizer,
)


def test_standard_generation(num_functions=10):
    """Test with standard function generation"""
    print("\n" + "="*70)
    print("TEST 1: Standard Function Generation")
    print("="*70)
    
    generator = JITFunctionGenerator(
        spread_allocation=False,
        use_optimizer=False
    )
    functions = generator.generate(num_functions)
    generator.warmup(iterations=5000)
    
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    scanner.print_results()
    
    return scanner, generator


def test_optimized_generation(num_functions=10, stencil_json=None):
    """Test with optimized function generation"""
    print("\n" + "="*70)
    print("TEST 2: Optimized Function Generation (High-Gadget-Density)")
    print("="*70)
    
    generator = JITFunctionGenerator(
        spread_allocation=False,
        use_optimizer=True,
        stencil_json_path=stencil_json
    )
    functions = generator.generate(num_functions)
    generator.warmup(iterations=5000)
    
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    scanner.print_results()
    
    return scanner, generator


def main():
    parser = argparse.ArgumentParser(
        description='Compare standard vs optimized function generation'
    )
    parser.add_argument(
        '-n', '--num-functions',
        type=int,
        default=10,
        help='Number of JIT functions to generate (default: 10)'
    )
    parser.add_argument(
        '--stencil-json',
        help='Path to stencil_gadgets.json (optional)'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("Stencil Optimization Comparison Test")
    print("="*70)
    print(f"Configuration:")
    print(f"  Number of functions: {args.num_functions}")
    if args.stencil_json:
        print(f"  Stencil data: {args.stencil_json}")
    print("="*70)
    
    # Show optimization recommendations first
    optimizer = StencilOptimizer(args.stencil_json)
    print("\n" + "="*70)
    print("OPTIMIZATION STRATEGY")
    print("="*70)
    for rec in optimizer.get_optimization_recommendations():
        print(f"  {rec}")
    
    # Run tests
    scanner_std, gen_std = test_standard_generation(args.num_functions)
    scanner_opt, gen_opt = test_optimized_generation(
        args.num_functions,
        args.stencil_json
    )
    
    # Comparison
    print("\n" + "="*70)
    print("COMPARISON: Standard vs Optimized")
    print("="*70)
    
    total_std = sum(len(v) for v in scanner_std.gadgets.values())
    total_opt = sum(len(v) for v in scanner_opt.gadgets.values())
    improvement = total_opt / total_std if total_std > 0 else 0
    
    print(f"\n[Gadget Count Comparison]")
    print(f"  Standard:  {total_std:>5} gadgets")
    print(f"  Optimized: {total_opt:>5} gadgets")
    print(f"  Improvement: {improvement:.2f}x")
    
    if improvement >= 1.2:
        print(f"\n  ✅ OPTIMIZATION SUCCESSFUL: {improvement:.2f}x improvement")
    elif improvement >= 1.05:
        print(f"\n  ⚠️  MODEST IMPROVEMENT: {improvement:.2f}x (5-20% gain)")
    else:
        print(f"\n  ❌ NO SIGNIFICANT IMPROVEMENT: {improvement:.2f}x")
    
    # Detailed comparison by gadget type
    print(f"\n[Gadget Type Breakdown]")
    all_types = set(scanner_std.gadgets.keys()) | set(scanner_opt.gadgets.keys())
    for gtype in sorted(all_types):
        count_std = len(scanner_std.gadgets.get(gtype, []))
        count_opt = len(scanner_opt.gadgets.get(gtype, []))
        type_improvement = count_opt / count_std if count_std > 0 else 0
        print(f"  {gtype:<12}: Std={count_std:>4}, Opt={count_opt:>4}, "
              f"Improvement={type_improvement:.2f}x")
    
    # Summaries
    GadgetReporter.print_summary("Standard Generation", scanner_std, gen_std)
    GadgetReporter.print_summary("Optimized Generation", scanner_opt, gen_opt)
    
    print("\n" + "="*70)
    print("TEST COMPLETED")
    print("="*70)


if __name__ == '__main__':
    main()
