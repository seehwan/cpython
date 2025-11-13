#!/usr/bin/env python3
"""
Gadget Reporter Module
=======================

Statistical analysis and reporting utilities for gadget analysis.
"""

import math


class GadgetReporter:
    """Statistical analysis and reporting for gadget experiments"""
    
    @staticmethod
    def print_summary(label, scanner, generator):
        """
        Print comprehensive summary of scan results
        
        Args:
            label: Test label (e.g., "Normal Allocation")
            scanner: RuntimeJITScanner instance
            generator: JITFunctionGenerator instance
        """
        print("\n" + "-"*70)
        print(f"SUMMARY: {label}")
        print("-"*70)
        
        gen_stats = generator.get_stats()
        scan_stats = scanner.get_stats()
        
        print(f"  JIT generate time : {gen_stats['generation_time']:.2f}s")
        print(f"  Warm-up time      : {gen_stats['warmup_time']:.2f}s")
        print(f"  Scan time         : {scan_stats['scan_time']:.2f}s")
        print(f"  JIT code bytes    : {scan_stats['total_bytes_scanned']:,} bytes")
        print(f"  Functions scanned : {gen_stats['total_functions']}")
        print(f"  JIT accessible    : {scan_stats['jit_memory_accessible']}")
        
        # Gadget counts (sorted by count descending)
        gadget_counts = {
            name: len(gadgets)
            for name, gadgets in scanner.gadgets.items()
        }
        sorted_gadgets = sorted(gadget_counts.items(), 
                               key=lambda x: x[1], reverse=True)
        
        print(f"  Gadget counts     :")
        for name, count in sorted_gadgets:
            print(f"    - {name:<10}: {count}")
    
    @staticmethod
    def analyze_gadget_factors(scanner_normal, scanner_spread):
        """
        Analyze factors affecting gadget yield between normal and spread
        
        Args:
            scanner_normal: Scanner from normal allocation test
            scanner_spread: Scanner from spread allocation test
        """
        print("\n" + "-"*70)
        print("ANALYSIS: Factors affecting gadget yield")
        print("-"*70)
        
        total_normal = sum(len(v) for v in scanner_normal.gadgets.values())
        total_spread = sum(len(v) for v in scanner_spread.gadgets.values())
        ratio = total_spread / total_normal if total_normal > 0 else 0
        
        print(f"  Spread vs Normal gadget yield: {total_spread} vs {total_normal} "
              f"({ratio:.2f}x)")
        
        # Factor analysis
        factors = []
        
        # 1. Address diversity
        diversity_normal = sum(
            len(vals) for vals in scanner_normal.address_diversity.values()
        )
        diversity_spread = sum(
            len(vals) for vals in scanner_spread.address_diversity.values()
        )
        
        if diversity_spread > diversity_normal * 1.1:
            factors.append("1) Address diversity: SIGNIFICANT impact")
        else:
            factors.append("1) Address diversity helps modestly at this scale.")
        
        # 2. Function count
        factors.append("2) Function count: yields scale roughly with number of JIT functions.")
        
        # 3. Warm-up iterations
        factors.append("3) Warm-up iterations: ensure Tier-2 JIT (>=~5000) "
                      "to increase stability and size.")
        
        # 4. Byte patterns
        factors.append("4) Byte patterns (magic values) influence incidental "
                      "pop/ret frequency.")
        
        for factor in factors:
            print(f"  {factor}")
    
    @staticmethod
    def compare_allocations(scanner_normal, scanner_spread):
        """
        Compare normal vs spread allocation results
        
        Args:
            scanner_normal: Scanner from normal allocation test
            scanner_spread: Scanner from spread allocation test
        """
        print("\n" + "="*70)
        print("COMPARISON: Normal vs Spread Allocation")
        print("="*70)
        
        # Gadget count comparison
        print("\n[Gadget Count Comparison]")
        all_gadget_names = set(scanner_normal.gadgets.keys()) | set(
            scanner_spread.gadgets.keys()
        )
        
        for name in sorted(all_gadget_names):
            count_normal = len(scanner_normal.gadgets.get(name, []))
            count_spread = len(scanner_spread.gadgets.get(name, []))
            improvement = count_spread / count_normal if count_normal > 0 else 0
            
            print(f"  {name:<12}: Normal={count_normal:>4}, "
                  f"Spread={count_spread:>4}, Improvement={improvement:.2f}x")
        
        # Address diversity comparison
        print("\n[Address Diversity Comparison]")
        print("  (Byte 위치별 unique 값 개수)")
        for byte_pos in range(8):
            unique_normal = len(scanner_normal.address_diversity[byte_pos])
            unique_spread = len(scanner_spread.address_diversity[byte_pos])
            improvement = unique_spread / unique_normal if unique_normal > 0 else 0
            
            print(f"    Byte {byte_pos}: Normal={unique_normal:>3}, "
                  f"Spread={unique_spread:>3}, Improvement={improvement:.2f}x")
        
        # Performance comparison
        print("\n[Performance Comparison]")
        print(f"  Normal scan time: {scanner_normal.stats['scan_time']:.2f}s")
        print(f"  Spread scan time: {scanner_spread.stats['scan_time']:.2f}s")
        
        # Overall results
        print("\n[Overall Results]")
        total_normal = sum(len(v) for v in scanner_normal.gadgets.values())
        total_spread = sum(len(v) for v in scanner_spread.gadgets.values())
        overall_improvement = total_spread / total_normal if total_normal > 0 else 0
        
        print(f"  Normal total gadgets: {total_normal}")
        print(f"  Spread total gadgets: {total_spread}")
        print(f"  Overall improvement: {overall_improvement:.2f}x")
        
        # Hypothesis check
        if overall_improvement >= 1.5:
            print("\n  ✅ HYPOTHESIS CONFIRMED: Significant improvement with spread allocation")
        elif overall_improvement >= 1.1:
            print("\n  ⚠️  HYPOTHESIS PARTIALLY CONFIRMED: Modest improvement")
        else:
            print(f"\n  ❌ HYPOTHESIS NOT CONFIRMED: Only {overall_improvement:.2f}x improvement")
    
    @staticmethod
    def print_classification_summary(classifier):
        """
        Print classification summary
        
        Args:
            classifier: GadgetClassifier instance
        """
        stats = classifier.get_statistics()
        
        print("\n" + "-"*70)
        print("CLASSIFICATION SUMMARY")
        print("-"*70)
        
        total = sum(stats['by_category'].values())
        print(f"  Total classified gadgets: {total}")
        
        print("\n  By Category:")
        for category, count in sorted(stats['by_category'].items(),
                                      key=lambda x: x[1], reverse=True):
            pct = (count / total * 100) if total > 0 else 0
            print(f"    {category:<25}: {count:>5} ({pct:>5.1f}%)")
        
        print("\n  By Gadget Type:")
        for gadget_type, categories in sorted(stats['by_gadget_type'].items()):
            print(f"    {gadget_type}:")
            for category, count in sorted(categories.items(),
                                          key=lambda x: x[1], reverse=True):
                print(f"      {category:<25}: {count:>4}")
