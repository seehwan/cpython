#!/usr/bin/env python3
"""
Quick test for JIT code generator with minimal functions
"""

import sys
import gc
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from gadget_analysis.generator import JITFunctionGenerator
from gadget_analysis.scanner import RuntimeJITScanner

def test_basic_generation():
    """Test basic JIT generation with 2 functions"""
    print("=" * 60)
    print("TEST: Basic JIT Generation (2 functions, 500 iters)")
    print("=" * 60)
    
    # 1. Generate functions
    print("\n[1/3] Generating 2 test functions...")
    generator = JITFunctionGenerator(use_optimizer=True)
    functions = generator.generate(count=2)
    print(f"[+] Generated {len(functions)} functions")
    
    # 2. Warmup
    print("\n[2/3] Warming up JIT compilation...")
    gc_was_enabled = gc.isenabled()
    gc.disable()
    
    try:
        warmup_iters = 500
        for i in range(warmup_iters):
            for func in functions:
                try:
                    func(42)  # Pass required argument
                except TypeError:
                    func()  # Try without argument if it doesn't need one
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{warmup_iters} iterations")
        print("[+] Warmup completed")
    finally:
        if gc_was_enabled:
            gc.enable()
    
    # 3. Scan
    print("\n[3/3] Scanning JIT memory...")
    scanner = RuntimeJITScanner()
    scanner.scan_functions(functions)
    
    print(f"\n[SUCCESS] Test completed!")
    print(f"  Functions scanned: {scanner.stats['functions_scanned']}")
    print(f"  Memory accessible: {scanner.stats['jit_memory_accessible']}")
    print(f"  Gadgets found: {scanner.stats['gadgets_found']}")
    print(f"  Scan time: {scanner.stats['scan_time']:.2f}s")
    
    return scanner

def test_scenario_a_mini():
    """Test Scenario A with minimal settings"""
    print("\n" + "=" * 60)
    print("TEST: Scenario A Mini (5 functions, 500 iters)")
    print("=" * 60)
    
    from gadget_analysis.jit_code_generator import JITCodeCapture
    
    capturer = JITCodeCapture()
    capturer.capture_standard_functions(
        count=5,
        iters=500,
        repeat=1,
        scenario_name='test_scenario_a'
    )
    
    # Check if file was created
    pkl_path = Path("gadget_analysis/jit_captures/test_scenario_a_run1.pkl")
    if pkl_path.exists():
        print(f"\n[SUCCESS] Data file created: {pkl_path}")
        print(f"  File size: {pkl_path.stat().st_size / 1024:.2f} KB")
        return True
    else:
        print(f"\n[ERROR] Data file not created: {pkl_path}")
        return False

def test_scenario_b_mini():
    """Test Scenario B with minimal settings"""
    print("\n" + "=" * 60)
    print("TEST: Scenario B Mini (2 regions: 1,5)")
    print("=" * 60)
    
    from gadget_analysis.jit_code_generator import JITCodeCapture
    
    capturer = JITCodeCapture()
    capturer.capture_memory_scaling(
        region_counts=[1, 5],
        iters=500,
        scenario_name='test_scenario_b'
    )
    
    # Check if file was created
    pkl_path = Path("gadget_analysis/jit_captures/test_scenario_b.pkl")
    if pkl_path.exists():
        print(f"\n[SUCCESS] Data file created: {pkl_path}")
        print(f"  File size: {pkl_path.stat().st_size / 1024:.2f} KB")
        return True
    else:
        print(f"\n[ERROR] Data file not created: {pkl_path}")
        return False

if __name__ == "__main__":
    start_time = time.time()
    
    try:
        # Test 1: Basic generation and scan
        print("\n" + "=" * 60)
        print("RUNNING TESTS")
        print("=" * 60)
        
        scanner = test_basic_generation()
        
        # Test 2: Scenario A mini
        success_a = test_scenario_a_mini()
        
        # Test 3: Scenario B mini
        success_b = test_scenario_b_mini()
        
        # Summary
        elapsed = time.time() - start_time
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"  Basic generation: PASSED")
        print(f"  Scenario A mini: {'PASSED' if success_a else 'FAILED'}")
        print(f"  Scenario B mini: {'PASSED' if success_b else 'FAILED'}")
        print(f"  Total time: {elapsed:.2f}s")
        
        if success_a and success_b:
            print("\n[SUCCESS] All tests passed! ✓")
            sys.exit(0)
        else:
            print("\n[ERROR] Some tests failed! ✗")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
