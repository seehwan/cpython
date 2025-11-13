#!/usr/bin/env python3
"""
Gadget Analysis Test Suite
===========================

Refactored test script using the gadget_analysis framework.

Usage:
    python3 test_gadget_analysis.py -n 50 -t both
    python3 test_gadget_analysis.py -n 100 -t normal --no-comparison
    python3 test_gadget_analysis.py -n 200 -t spread
"""

import argparse
import sys

sys.path.insert(0, '/home/mobileos2/cpython')

from gadget_analysis import (
    GadgetClassifier,
    RuntimeJITScanner,
    JITFunctionGenerator,
    GadgetReporter,
)


def test_normal_allocation(num_functions=1000):
    """Test with normal allocation (consecutive memory)"""
    print("\n" + "="*70)
    print("TEST 1: Normal Allocation (Consecutive Memory)")
    print("="*70)
    
    # Generate functions
    generator = JITFunctionGenerator(spread_allocation=False)
    functions = generator.generate(num_functions)
    
    # Warm up (5000+ iterations for Tier 2 JIT)
    generator.warmup(iterations=5000)
    
    # Scan JIT memory
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    # Print results
    scanner.print_results()
    scanner.export_results('runtime_scan_normal.json')
    
    return scanner, generator


def test_spread_allocation(num_functions=1000):
    """Test with spread allocation (wide memory distribution)"""
    print("\n" + "="*70)
    print("TEST 2: Spread Allocation (Wide Memory Distribution)")
    print("="*70)
    
    # Generate functions (spread)
    generator = JITFunctionGenerator(spread_allocation=True)
    functions = generator.generate(num_functions)
    
    # Warm up (5000+ iterations for Tier 2 JIT)
    generator.warmup(iterations=5000)
    
    # Scan JIT memory
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    # Print results
    scanner.print_results()
    scanner.export_results('runtime_scan_spread.json')
    
    return scanner, generator


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(
        description='Runtime JIT Memory Gadget Scanner Test'
    )
    parser.add_argument(
        '-n', '--num-functions',
        type=int,
        default=50,
        help='Number of JIT functions to generate (default: 50)'
    )
    parser.add_argument(
        '-t', '--test',
        choices=['normal', 'spread', 'both'],
        default='both',
        help='Test scenario to run (default: both)'
    )
    parser.add_argument(
        '--no-comparison',
        action='store_true',
        help='Skip comparison analysis'
    )
    
    args = parser.parse_args()
    
    # Print configuration
    print("="*70)
    print("Runtime JIT Memory Gadget Scanner Test")
    print("="*70)
    print(f"Configuration:")
    print(f"  Number of functions: {args.num_functions}")
    print(f"  Test scenario: {args.test}")
    print("="*70)
    
    # Run tests
    scanner_normal = None
    scanner_spread = None
    gen_normal = None
    gen_spread = None
    
    if args.test in ['normal', 'both']:
        scanner_normal, gen_normal = test_normal_allocation(args.num_functions)
    
    if args.test in ['spread', 'both']:
        scanner_spread, gen_spread = test_spread_allocation(args.num_functions)
    
    # Comparison and analysis
    if args.test == 'both' and not args.no_comparison:
        GadgetReporter.compare_allocations(scanner_normal, scanner_spread)
    
    # Print summaries
    if scanner_normal:
        GadgetReporter.print_summary("Normal Allocation", scanner_normal, gen_normal)
    
    if scanner_spread:
        GadgetReporter.print_summary("Spread Allocation", scanner_spread, gen_spread)
    
    # Factor analysis
    if args.test == 'both' and not args.no_comparison:
        GadgetReporter.analyze_gadget_factors(scanner_normal, scanner_spread)
    
    print("\n" + "="*70)
    print("TEST COMPLETED")
    print("="*70)


if __name__ == '__main__':
    main()
