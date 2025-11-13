#!/usr/bin/env python3
"""
Stencil Optimization Test (Case Study 4)
=========================================

Tests standard vs optimized function generation for gadget analysis.

Usage:
    cd /home/mobileos2/cpython/case_studies/case4
    python3 test_stencil_opt.py -n 10
"""

import sys
sys.path.insert(0, '/home/mobileos2')

from gadget_analysis import (
    JITFunctionGenerator,
    RuntimeJITScanner,
    GadgetReporter,
    StencilOptimizer,
)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Test stencil optimization')
    parser.add_argument('-n', '--num-functions', type=int, default=10)
    args = parser.parse_args()
    
    print("="*70)
    print("Stencil Optimization Test")
    print("="*70)
    print(f"Functions: {args.num_functions}")
    
    # Show optimization strategy
    optimizer = StencilOptimizer()
    print("\n[Optimization Strategy]")
    for rec in optimizer.get_optimization_recommendations()[:5]:
        print(f"  {rec}")
    
    # Test 1: Standard
    print("\n" + "="*70)
    print("TEST 1: Standard Generation")
    print("="*70)
    
    gen_std = JITFunctionGenerator(use_optimizer=False)
    funcs_std = gen_std.generate(args.num_functions)
    gen_std.warmup(5000)
    
    scan_std = RuntimeJITScanner()
    scan_std.scan_functions(funcs_std)
    
    total_std = sum(len(v) for v in scan_std.gadgets.values())
    print(f"\n[Result] Standard: {total_std} gadgets")
    
    # Test 2: Optimized
    print("\n" + "="*70)
    print("TEST 2: Optimized Generation (High-Gadget-Density)")
    print("="*70)
    
    gen_opt = JITFunctionGenerator(use_optimizer=True)
    funcs_opt = gen_opt.generate(args.num_functions)
    gen_opt.warmup(5000)
    
    scan_opt = RuntimeJITScanner()
    scan_opt.scan_functions(funcs_opt)
    
    total_opt = sum(len(v) for v in scan_opt.gadgets.values())
    print(f"\n[Result] Optimized: {total_opt} gadgets")
    
    # Comparison
    print("\n" + "="*70)
    print("COMPARISON")
    print("="*70)
    improvement = total_opt / total_std if total_std > 0 else 0
    print(f"  Standard:  {total_std:>5} gadgets")
    print(f"  Optimized: {total_opt:>5} gadgets")
    print(f"  Improvement: {improvement:.2f}x")
    
    if improvement >= 1.2:
        print(f"\n  ✅ SUCCESS: {improvement:.2f}x improvement!")
    elif improvement >= 1.05:
        print(f"\n  ⚠️  MODEST: {improvement:.2f}x")
    else:
        print(f"\n  ❌ NO IMPROVEMENT: {improvement:.2f}x")
    
    print("\n" + "="*70)


if __name__ == '__main__':
    main()
