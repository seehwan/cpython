#!/usr/bin/env python3
"""
Runtime JIT Memory Gadget Scanner Test
======================================

이 스크립트는 PATCH_GADGET_ANALYSIS.md에서 분석한 런타임 JIT 메모리 스캔 기법을 
실제로 테스트합니다.

핵심 아이디어:
1. 많은 JIT 함수 생성 (gadget spray)
2. 런타임에 패치된 JIT 메모리 직접 스캔
3. patch_64, patch_x86_64_32rx, patch_32r에서 우연히 생긴 gadget 발견
4. Unintended instruction 활용 (8개 오프셋)

테스트 시나리오:
- Normal allocation: 연속 메모리에 함수 생성
- Spread allocation: 넓은 영역에 분산 생성 (주소 다양성 극대화)
"""

import ctypes
import struct
import time
import json
import types
from collections import defaultdict
from capstone import *
import jitexecleak

# ============================================================================
# Configuration
# ============================================================================

# Gadget 패턴 정의
GADGET_PATTERNS = {
    'pop_rax': b'\x58',           # pop rax (0x58)
    'pop_rdi': b'\x5f',           # pop rdi (0x5f)
    'pop_rsi': b'\x5e',           # pop rsi (0x5e)
    'pop_rdx': b'\x5a',           # pop rdx (0x5a)
    'pop_rbx': b'\x5b',           # pop rbx (0x5b)
    'pop_rcx': b'\x59',           # pop rcx (0x59)
    'syscall': b'\x0f\x05',       # syscall (0x0f 0x05)
    'ret': b'\xc3',               # ret (0xc3)
}

# ============================================================================
# JIT Function Generator
# ============================================================================

class JITFunctionGenerator:
    """JIT 함수 생성기 (Normal vs Spread allocation)"""
    
    def __init__(self, spread_allocation=False):
        self.spread_allocation = spread_allocation
        self.functions = []
        self.modules = []
        self.stats = {
            'total_functions': 0,
            'jit_compiled': 0,
            'jit_failed': 0,
            'generation_time': 0,
            'warmup_time': 0,
        }
    
    def generate(self, count=1000):
        """
        JIT 함수 생성
        
        Parameters:
        - count: 생성할 함수 개수
        """
        start_time = time.time()
        
        if self.spread_allocation:
            print(f"[*] Generating {count} functions with SPREAD allocation...")
            self._generate_spread(count)
        else:
            print(f"[*] Generating {count} functions with NORMAL allocation...")
            self._generate_normal(count)
        
        self.stats['generation_time'] = time.time() - start_time
        self.stats['total_functions'] = len(self.functions)
        
        print(f"[+] Generated {len(self.functions)} functions in {self.stats['generation_time']:.2f}s")
        return self.functions
    
    def _generate_normal(self, count):
        """일반 생성: 연속된 메모리 영역"""
        for i in range(count):
            func = self._create_jit_function(i)
            self.functions.append(func)
            
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{count} functions generated")
    
    def _generate_spread(self, count):
        """
        분산 생성: 넓은 주소 영역에 배치
        
        전략:
        1. 10개 모듈 생성
        2. 각 모듈에 함수 분산
        3. 메모리 할당 강제 분산
        """
        num_modules = 10
        funcs_per_module = count // num_modules
        
        for mod_idx in range(num_modules):
            # 새 모듈 생성
            module = types.ModuleType(f"jit_spread_module_{mod_idx}")
            self.modules.append(module)
            
            print(f"  Module {mod_idx}: generating {funcs_per_module} functions...")
            
            # 각 모듈에 함수 생성
            for i in range(funcs_per_module):
                global_idx = mod_idx * funcs_per_module + i
                func = self._create_jit_function(global_idx)
                
                # 모듈 네임스페이스에 등록
                setattr(module, f"func_{i}", func)
                self.functions.append(func)
            
            # 메모리 할당 경계 강제 생성 (다음 모듈이 다른 주소에 할당되도록)
            dummy = bytearray(1024 * 1024)  # 1MB 더미
        
        print(f"[+] Functions spread across {len(self.modules)} modules")
    
    def _create_jit_function(self, seed):
        """
        단일 JIT 함수 생성 (gadget_chain_parallel.py의 검증된 패턴 사용)
        
        다양한 stencil 활용:
        - CALL (nested function)
        - STORE_SUBSCR_DICT, LOAD_ATTR
        - COMPARE_OP
        - FOR_ITER
        - BINARY_OP (add, mul, xor, shift)
        """
        # MAGIC_VALUES from gadget_chain_parallel.py
        magic_values = [
            0x000000C3, 0x00005FC3, 0x00005EC3, 0x00005AC3,
            0x00005BC3, 0x000031D2, 0x004831C0,
        ]
        magic_value = magic_values[seed % len(magic_values)]
        
        code = f"""
def jit_func_{seed}(x):
    # Nested helper to trigger CALL-related stencils
    def h(a, b):
        return (a ^ b) & 0xFFFFFFFF

    # Dictionary and object operations to trigger STORE_SUBSCR_DICT, LOAD_ATTR, COMPARE_OP stencils
    d = {{}}
    class Obj:
        val = 0

    obj = Obj()
    acc = x
    for i in range({3000 + seed * 500}):
        acc ^= ({magic_value} + (i << (i % 8)))
        acc = ((acc << (i % 5)) | (acc >> (32 - (i % 5)))) & 0xFFFFFFFF
        acc += ({magic_value} >> (i % 16))
        acc *= 3 + (i % 4)
        acc ^= (acc >> ((i+3) % 8))
        acc ^= ({magic_value} + i) * ((acc >> 3) & 0xff)
        acc += (i ^ {magic_value})
        
        # Trigger various stencils
        acc = h(acc, i & 0xff)
        
        if i % 100 == 0:
            d[i] = acc & 0xff
            acc ^= d.get(i, 0)
        
        if i % 200 == 0:
            obj.val = acc & 0xffff
            acc += obj.val
        
        if acc > {magic_value}:
            acc -= 1
        elif acc < (i & 0xff):
            acc += 1
    
    return acc
"""
        scope = {}
        exec(code, scope)
        return scope[f'jit_func_{seed}']
    
    def warmup(self, iterations=5000):
        """JIT 컴파일 유도 (warm-up) - 더 많은 반복으로 tier 2 활성화"""
        start_time = time.time()
        print(f"[*] Warming up {len(self.functions)} functions ({iterations} iterations each)...")
        
        for i, func in enumerate(self.functions):
            try:
                for _ in range(iterations):
                    func(42)
                self.stats['jit_compiled'] += 1
            except Exception as e:
                self.stats['jit_failed'] += 1
                print(f"[!] Function {i} warmup failed: {e}")
            
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{len(self.functions)} functions warmed up")
        
        self.stats['warmup_time'] = time.time() - start_time
        print(f"[+] Warm-up completed in {self.stats['warmup_time']:.2f}s")
        print(f"    JIT compiled: {self.stats['jit_compiled']}")
        print(f"    Failed: {self.stats['jit_failed']}")

# ============================================================================
# Runtime JIT Memory Scanner
# ============================================================================

class RuntimeJITScanner:
    """런타임 JIT 메모리 스캐너"""
    
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.gadgets = defaultdict(list)
        self.stats = {
            'functions_scanned': 0,
            'jit_memory_accessible': 0,
            'jit_memory_failed': 0,
            'total_bytes_scanned': 0,
            'scan_time': 0,
            'gadgets_found': 0,
        }
        self.address_diversity = defaultdict(set)  # 바이트별 주소 다양성 측정
    
    def scan_functions(self, functions):
        """모든 JIT 함수 스캔"""
        start_time = time.time()
        print(f"\n[*] Scanning {len(functions)} JIT functions...")
        
        for i, func in enumerate(functions):
            self._scan_single_function(func, i)
            
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{len(functions)} functions scanned")
        
        self.stats['scan_time'] = time.time() - start_time
        self.stats['functions_scanned'] = len(functions)
        self.stats['gadgets_found'] = sum(len(v) for v in self.gadgets.values())
        
        print(f"[+] Scan completed in {self.stats['scan_time']:.2f}s")
        print(f"    Memory accessible: {self.stats['jit_memory_accessible']}")
        print(f"    Memory failed: {self.stats['jit_memory_failed']}")
        print(f"    Total bytes scanned: {self.stats['total_bytes_scanned']:,}")
        print(f"    Gadgets found: {self.stats['gadgets_found']}")
        
        return self.gadgets
    
    def _scan_single_function(self, func, func_idx):
        """단일 JIT 함수 메모리 스캔"""
        try:
            # JIT 코드 주소 얻기
            jit_addr, jit_size = jitexecleak.leak_executor_jit(func)
            
            # 메모리 읽기
            buffer = ctypes.string_at(jit_addr, jit_size)
            self.stats['jit_memory_accessible'] += 1
            self.stats['total_bytes_scanned'] += jit_size
            
            # Gadget 스캔 (모든 바이트 오프셋 - Unintended 포함)
            self._scan_buffer_for_gadgets(jit_addr, buffer)
            
            # 주소 다양성 측정 (patch_64 분석용)
            self._measure_address_diversity(buffer)
            
        except Exception as e:
            self.stats['jit_memory_failed'] += 1
    
    def _scan_buffer_for_gadgets(self, base_addr, buffer):
        """버퍼에서 gadget 패턴 탐색"""
        for offset in range(len(buffer) - 8):
            # 각 gadget 패턴 체크
            for gadget_name, pattern in GADGET_PATTERNS.items():
                if buffer[offset:offset+len(pattern)] == pattern:
                    gadget_addr = base_addr + offset
                    
                    # Capstone으로 검증 (실제 명령어인지)
                    try:
                        insns = list(self.md.disasm(buffer[offset:offset+16], gadget_addr))
                        if insns:
                            self.gadgets[gadget_name].append({
                                'address': gadget_addr,
                                'offset': offset,
                                'bytes': buffer[offset:offset+8].hex(),
                                'instruction': f"{insns[0].mnemonic} {insns[0].op_str}",
                            })
                    except:
                        pass
    
    def _measure_address_diversity(self, buffer):
        """
        패치된 주소의 바이트별 다양성 측정
        
        patch_64 (8바이트) 패치 값에서 각 바이트 위치의 엔트로피 측정
        JIT 영역이 넓을수록 상위 바이트도 다양해짐
        """
        # 8바이트 정렬된 위치에서 포인터 크기 값 추출
        for offset in range(0, len(buffer) - 8, 8):
            ptr_value = struct.unpack('<Q', buffer[offset:offset+8])[0]
            
            # libc 주소 범위 (0x7f로 시작)인지 확인
            if ptr_value > 0x7f0000000000 and ptr_value < 0x800000000000:
                # 각 바이트 위치의 값 기록
                for byte_pos in range(8):
                    byte_val = (ptr_value >> (byte_pos * 8)) & 0xFF
                    self.address_diversity[byte_pos].add(byte_val)
    
    def print_results(self):
        """스캔 결과 출력"""
        print("\n" + "="*70)
        print("SCAN RESULTS")
        print("="*70)
        
        # Gadget 통계
        print("\n[Gadgets Found]")
        for gadget_name, gadget_list in sorted(self.gadgets.items()):
            print(f"  {gadget_name:<12}: {len(gadget_list):>6} gadgets")
        
        # 샘플 gadget 출력 (각 타입당 3개)
        print("\n[Sample Gadgets]")
        for gadget_name, gadget_list in sorted(self.gadgets.items()):
            if gadget_list:
                print(f"\n  {gadget_name}:")
                for gadget in gadget_list[:3]:
                    print(f"    0x{gadget['address']:016x}: {gadget['instruction']}")
        
        # 주소 다양성 분석
        print("\n[Address Diversity Analysis]")
        print("  (patch_64 주소의 바이트별 엔트로피)")
        for byte_pos in range(8):
            unique_vals = len(self.address_diversity[byte_pos])
            entropy = 0
            if unique_vals > 0:
                import math
                entropy = math.log2(unique_vals) if unique_vals > 1 else 0
            print(f"    Byte {byte_pos}: {unique_vals:>3} unique values ({entropy:.2f} bits entropy)")
        
        print("\n" + "="*70)
    
    def export_results(self, filename):
        """결과를 JSON으로 저장"""
        data = {
            'stats': self.stats,
            'gadgets': {
                name: [
                    {
                        'address': f"0x{g['address']:016x}",
                        'offset': g['offset'],
                        'bytes': g['bytes'],
                        'instruction': g['instruction'],
                    }
                    for g in gadgets
                ]
                for name, gadgets in self.gadgets.items()
            },
            'address_diversity': {
                f'byte_{i}': len(vals)
                for i, vals in self.address_diversity.items()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Results exported to {filename}")

# ============================================================================
# Test Scenarios
# ============================================================================

def test_normal_allocation(num_functions=1000):
    """테스트 1: Normal allocation (연속 메모리)"""
    print("\n" + "="*70)
    print("TEST 1: Normal Allocation (Consecutive Memory)")
    print("="*70)
    
    # 1. 함수 생성
    generator = JITFunctionGenerator(spread_allocation=False)
    functions = generator.generate(num_functions)
    
    # 2. Warm-up
    generator.warmup(iterations=100)
    
    # 3. 스캔
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    # 4. 결과 출력
    scanner.print_results()
    scanner.export_results('runtime_scan_normal.json')
    
    return scanner, generator

def test_spread_allocation(num_functions=1000):
    """테스트 2: Spread allocation (넓은 영역 분산)"""
    print("\n" + "="*70)
    print("TEST 2: Spread Allocation (Wide Memory Distribution)")
    print("="*70)
    
    # 1. 함수 생성 (spread)
    generator = JITFunctionGenerator(spread_allocation=True)
    functions = generator.generate(num_functions)
    
    # 2. Warm-up
    generator.warmup(iterations=100)
    
    # 3. 스캔
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    # 4. 결과 출력
    scanner.print_results()
    scanner.export_results('runtime_scan_spread.json')
    
    return scanner, generator

# ----------------------------------------------------------------------------
# Summary and Analysis Utilities
# ----------------------------------------------------------------------------
def print_summary(label, scanner, generator):
    print("\n" + "-"*70)
    print(f"SUMMARY: {label}")
    print("-"*70)
    # Times
    print(f"  JIT generate time : {generator.stats.get('generation_time', 0):.2f}s")
    print(f"  Warm-up time      : {generator.stats.get('warmup_time', 0):.2f}s")
    print(f"  Scan time         : {scanner.stats.get('scan_time', 0):.2f}s")
    # Sizes and counts
    print(f"  JIT code bytes    : {scanner.stats.get('total_bytes_scanned', 0):,} bytes")
    print(f"  Functions scanned : {scanner.stats.get('functions_scanned', 0)}")
    print(f"  JIT accessible    : {scanner.stats.get('jit_memory_accessible', 0)}")
    # Gadget counts sorted
    counts = [(k, len(v)) for k, v in scanner.gadgets.items()]
    counts.sort(key=lambda x: x[1], reverse=True)
    print("  Gadget counts     :")
    for k, c in counts:
        print(f"    - {k:<10}: {c}")

def analyze_gadget_factors(scanner_normal=None, scanner_spread=None):
    print("\n" + "-"*70)
    print("ANALYSIS: Factors affecting gadget yield")
    print("-"*70)
    # Heuristics based on observed stats
    def total_gadgets(scanner):
        return sum(len(v) for v in scanner.gadgets.values()) if scanner else 0
    normal_total = total_gadgets(scanner_normal)
    spread_total = total_gadgets(scanner_spread)
    if scanner_normal and scanner_spread:
        improvement = (spread_total / normal_total) if normal_total > 0 else 0
        print(f"  Spread vs Normal gadget yield: {spread_total} vs {normal_total} ({improvement:.2f}x)")
        if improvement > 1.2:
            print("  1) Address diversity (spread allocation) appears most impactful.")
        else:
            print("  1) Address diversity helps modestly at this scale.")
        print("  2) Function count: yields scale roughly with number of JIT functions.")
        print("  3) Warm-up iterations: ensure Tier-2 JIT (>=~5000) to increase stability and size.")
        print("  4) Byte patterns (magic values) influence incidental pop/ret frequency.")
    else:
        print("  1) Function count: more functions → more chances for pop/ret patterns.")
        print("  2) Address diversity: spreading modules widens patch_64 values.")
        print("  3) Warm-up iterations: higher can improve executor availability and code size.")
        print("  4) Magic constants and loop structure affect incidental sequences.")

def compare_results(scanner_normal, scanner_spread):
    """두 테스트 결과 비교"""
    print("\n" + "="*70)
    print("COMPARISON: Normal vs Spread Allocation")
    print("="*70)
    
    print("\n[Gadget Count Comparison]")
    all_gadget_types = set(scanner_normal.gadgets.keys()) | set(scanner_spread.gadgets.keys())
    
    for gadget_name in sorted(all_gadget_types):
        normal_count = len(scanner_normal.gadgets.get(gadget_name, []))
        spread_count = len(scanner_spread.gadgets.get(gadget_name, []))
        improvement = (spread_count / normal_count) if normal_count > 0 else 0
        
        print(f"  {gadget_name:<12}: Normal={normal_count:>4}, Spread={spread_count:>4}, "
              f"Improvement={improvement:>.2f}x")
    
    print("\n[Address Diversity Comparison]")
    print("  (Byte 위치별 unique 값 개수)")
    for byte_pos in range(8):
        normal_div = len(scanner_normal.address_diversity[byte_pos])
        spread_div = len(scanner_spread.address_diversity[byte_pos])
        improvement = (spread_div / normal_div) if normal_div > 0 else 0
        
        print(f"    Byte {byte_pos}: Normal={normal_div:>3}, Spread={spread_div:>3}, "
              f"Improvement={improvement:>.2f}x")
    
    print("\n[Performance Comparison]")
    print(f"  Normal scan time: {scanner_normal.stats['scan_time']:.2f}s")
    print(f"  Spread scan time: {scanner_spread.stats['scan_time']:.2f}s")
    
    total_normal = sum(len(v) for v in scanner_normal.gadgets.values())
    total_spread = sum(len(v) for v in scanner_spread.gadgets.values())
    total_improvement = (total_spread / total_normal) if total_normal > 0 else 0
    
    print(f"\n[Overall Results]")
    print(f"  Normal total gadgets: {total_normal}")
    print(f"  Spread total gadgets: {total_spread}")
    print(f"  Overall improvement: {total_improvement:.2f}x")
    
    if total_improvement >= 2.0:
        print(f"\n  ✅ HYPOTHESIS CONFIRMED: Spread allocation improves gadget yield by {total_improvement:.2f}x!")
    elif total_improvement > 1.1:
        print(f"\n  ⚠️  HYPOTHESIS PARTIALLY CONFIRMED: {total_improvement:.2f}x improvement")
    else:
        print(f"\n  ❌ HYPOTHESIS NOT CONFIRMED: Only {total_improvement:.2f}x improvement")

# ============================================================================
# Main
# ============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Runtime JIT Memory Gadget Scanner Test')
    parser.add_argument('-n', '--num-functions', type=int, default=1000,
                        help='Number of JIT functions to generate (default: 1000)')
    parser.add_argument('-t', '--test', choices=['normal', 'spread', 'both'], default='both',
                        help='Test scenario to run (default: both)')
    parser.add_argument('--no-comparison', action='store_true',
                        help='Skip comparison (only run tests)')
    
    args = parser.parse_args()
    
    print("="*70)
    print("Runtime JIT Memory Gadget Scanner Test")
    print("="*70)
    print(f"Configuration:")
    print(f"  Number of functions: {args.num_functions}")
    print(f"  Test scenario: {args.test}")
    print("="*70)
    
    scanner_normal = None
    scanner_spread = None
    gen_normal = None
    gen_spread = None
    
    # Run tests
    if args.test in ['normal', 'both']:
        scanner_normal, gen_normal = test_normal_allocation(args.num_functions)
    
    if args.test in ['spread', 'both']:
        scanner_spread, gen_spread = test_spread_allocation(args.num_functions)
    
    # Compare results
    if args.test == 'both' and not args.no_comparison:
        compare_results(scanner_normal, scanner_spread)

    # Summaries
    if scanner_normal:
        print_summary('Normal Allocation', scanner_normal, gen_normal)
    if scanner_spread:
        print_summary('Spread Allocation', scanner_spread, gen_spread)

    # Factor analysis when both present
    if scanner_normal and scanner_spread:
        analyze_gadget_factors(scanner_normal, scanner_spread)
    
    print("\n" + "="*70)
    print("TEST COMPLETED")
    print("="*70)

if __name__ == "__main__":
    main()
