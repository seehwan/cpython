#!/usr/bin/env python3
"""
JIT Code Generator - 실험들이 공유할 JIT 코드 생성 및 메모리 덤프 저장
각 시나리오별로 한 번만 실행하여 패치 전/후 메모리 이미지를 저장
"""
import json
import pickle
from pathlib import Path
from typing import Dict, List, Tuple
import sys
import gc

from gadget_analysis.generator import JITFunctionGenerator
from gadget_analysis.scanner import RuntimeJITScanner


class JITCodeCapture:
    """JIT 코드 생성 및 메모리 캡처"""
    
    def __init__(self, output_dir: str = "gadget_analysis/jit_captures"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def capture_standard_functions(self, count: int = 100, iters: int = 6000, repeat: int = 1, scenario_name: str = "scenario_a"):
        """
        Scenario A: 표준 함수 생성 (실험 1, 2, 3 공유)
        - 다양한 opcode 조합
        - 패치 전/후 메모리 덤프
        """
        print(f"\n{'='*60}")
        print(f"SCENARIO A: Standard JIT Functions ({count} functions, repeats={repeat})")
        print(f"{'='*60}")

        last_capture = None
        run_index = []

        for r in range(1, int(max(1, repeat)) + 1):
            print(f"\n--- Run {r}/{repeat} ---")

            # 1. JIT 함수 생성 및 워밍업
            print(f"\n[1/5] Generating {count} test functions...")
            generator = JITFunctionGenerator(use_optimizer=True)
            functions = generator.generate(count=count)

            print(f"[2/5] Warming up JIT compilation (this takes time)...")
            # 진행률 표시를 위해 청크 단위 워밍업
            total_iters = int(iters)
            chunk = 200
            done = 0
            gc_disable_prev = gc.isenabled()
            try:
                gc.disable()
                while done < total_iters:
                    step = min(chunk, total_iters - done)
                    generator.warmup(iterations=step)
                    done += step
                    percent = int(done / total_iters * 100)
                    if percent % 5 == 0:
                        print(f"    - Warmup progress: {percent}% ({done}/{total_iters})", flush=True)
            finally:
                if gc_disable_prev:
                    gc.enable()

            # 2. 패치 전 메모리 스캔
            print(f"[3/5] Scanning JIT memory (before patch)...")
            scanner = RuntimeJITScanner()
            pre_patch_data = scanner.scan_memory()

            # 3. 패치 함수 호출 추적을 위한 후크 (선택적)
            print(f"[4/5] Triggering patch operations...")
            for func in functions[:10]:
                try:
                    func()
                except Exception:
                    pass

            # 4. 패치 후 메모리 스캔
            print(f"[5/5] Scanning JIT memory (after patch)...")
            post_patch_data = scanner.scan_memory()

            # 5. 데이터 저장
            capture_data = {
                'scenario': scenario_name,
                'run': r,
                'function_count': count,
                'warmup_iterations': total_iters,
                'pre_patch': pre_patch_data,
                'post_patch': post_patch_data,
                'functions': [
                    {
                        'name': f.__name__,
                        'code': f.__code__.co_code.hex(),
                        'address': hex(id(f))
                    }
                    for f in functions[:20]
                ]
            }

            # 개별 런 파일 저장
            run_file = self.output_dir / f"{scenario_name}_run{r}.pkl"
            with open(run_file, 'wb') as f:
                pickle.dump(capture_data, f)

            # 최신본을 시나리오 기본 파일로 갱신 (호환성)
            output_file = self.output_dir / f"{scenario_name}.pkl"
            with open(output_file, 'wb') as f:
                pickle.dump(capture_data, f)

            # 메타 저장
            meta_file = self.output_dir / f"{scenario_name}_run{r}_meta.json"
            with open(meta_file, 'w') as f:
                json.dump({
                    'scenario': scenario_name,
                    'run': r,
                    'function_count': count,
                    'warmup_iterations': total_iters,
                    'pre_patch_regions': len(pre_patch_data.get('regions', [])),
                    'post_patch_regions': len(post_patch_data.get('regions', [])),
                    'pre_patch_size': sum(rg.get('size', 0) for rg in pre_patch_data.get('regions', [])),
                    'post_patch_size': sum(rg.get('size', 0) for rg in post_patch_data.get('regions', []))
                }, f, indent=2)

            print(f"\n✓ Run {r}: data -> {run_file}")
            last_capture = capture_data
            run_index.append({
                'run': r,
                'file': str(run_file)
            })

        # 인덱스 메타 업데이트
        index_meta = self.output_dir / f"{scenario_name}_meta.json"
        with open(index_meta, 'w') as f:
            json.dump({
                'scenario': scenario_name,
                'repeats': repeat,
                'runs': run_index
            }, f, indent=2)

        print(f"\n✓ Latest capture saved to: {self.output_dir / f'{scenario_name}.pkl'}")
        print(f"✓ Index metadata saved to: {index_meta}")

        return last_capture
    
    def capture_memory_scaling(self, region_counts: List[int] = [1, 8, 32, 80], 
                               iters: int = 6000,
                               scenario_name: str = "scenario_b"):
        """
        Scenario B: 메모리 스케일링 (실험 4)
        - 여러 JIT 영역 할당
        - 각 영역별 가젯 카운트
        """
        print(f"\n{'='*60}")
        print(f"SCENARIO B: Memory Scaling (regions: {region_counts})")
        print(f"{'='*60}")
        
        all_captures = []
        
        for region_count in region_counts:
            print(f"\n[Region Count: {region_count}]")
            
            # 여러 generator 인스턴스로 영역 분산 시뮬레이션
            generators = []
            all_functions = []
            
            print(f"  Generating functions across {region_count} regions...")
            for i in range(region_count):
                gen = JITFunctionGenerator(use_optimizer=(i % 2 == 0))
                funcs = gen.generate(count=10)  # 영역당 10개 함수
                generators.append(gen)
                all_functions.extend(funcs)
            
            print(f"  Warming up {len(all_functions)} functions...")
            total_iters = int(iters)
            chunk = 300
            done = 0
            gc_disable_prev = gc.isenabled()
            try:
                gc.disable()
                while done < total_iters:
                    step = min(chunk, total_iters - done)
                    for gen in generators:
                        gen.warmup(iterations=step)
                    done += step
                    percent = int(done / total_iters * 100)
                    if percent % 10 == 0:
                        print(f"    - Warmup progress: {percent}% ({done}/{total_iters})", flush=True)
            finally:
                if gc_disable_prev:
                    gc.enable()
            
            print(f"  Scanning memory...")
            scanner = RuntimeJITScanner()
            memory_data = scanner.scan_memory()
            
            all_captures.append({
                'region_count': region_count,
                'memory_data': memory_data
            })
        
        # 저장
        output_file = self.output_dir / f"{scenario_name}.pkl"
        with open(output_file, 'wb') as f:
            pickle.dump(all_captures, f)
        
        meta_file = self.output_dir / f"{scenario_name}_meta.json"
        with open(meta_file, 'w') as f:
            json.dump({
                'scenario': scenario_name,
                'region_counts': region_counts,
                'captures': len(all_captures),
                'warmup_iterations': iters
            }, f, indent=2)
        
        print(f"\n✓ Captured data saved to: {output_file}")
        print(f"✓ Metadata saved to: {meta_file}")
        
        return all_captures
    
    def capture_syscall_taxonomy(self, count: int = 50, iters: int = 6000, scenario_name: str = "scenario_c"):
        """
        Scenario C: Ret-free Syscall Chains (실험 5)
        - syscall, pop, indirect branch 가젯 풀 확보
        """
        print(f"\n{'='*60}")
        print(f"SCENARIO C: Ret-Free Syscall Taxonomy ({count} functions)")
        print(f"{'='*60}")
        
        # syscall 가젯을 더 많이 생성하기 위한 특수 설정
        print(f"[1/3] Generating functions optimized for syscall gadgets...")
        generator = JITFunctionGenerator(use_optimizer=False)  # Optimizer off로 더 다양한 패턴
        functions = generator.generate(count=count)
        
        print(f"[2/3] Warming up...")
        total_iters = int(iters)
        chunk = 300
        done = 0
        gc_disable_prev = gc.isenabled()
        try:
            gc.disable()
            while done < total_iters:
                step = min(chunk, total_iters - done)
                generator.warmup(iterations=step)
                done += step
                percent = int(done / total_iters * 100)
                if percent % 10 == 0:
                    print(f"    - Warmup progress: {percent}% ({done}/{total_iters})", flush=True)
        finally:
            if gc_disable_prev:
                gc.enable()
        
        print(f"[3/3] Scanning for syscall gadgets...")
        scanner = RuntimeJITScanner()
        memory_data = scanner.scan_memory()
        
        capture_data = {
            'scenario': scenario_name,
            'function_count': count,
            'memory_data': memory_data
        }
        
        output_file = self.output_dir / f"{scenario_name}.pkl"
        with open(output_file, 'wb') as f:
            pickle.dump(capture_data, f)
        
        meta_file = self.output_dir / f"{scenario_name}_meta.json"
        with open(meta_file, 'w') as f:
            json.dump({
                'scenario': scenario_name,
                'function_count': count,
                'regions': len(memory_data.get('regions', [])),
                'warmup_iterations': total_iters
            }, f, indent=2)
        
        print(f"\n✓ Captured data saved to: {output_file}")
        return capture_data
    
    def capture_opcode_sensitive(self, count: int = 50, iters: int = 6000, scenario_name: str = "scenario_d"):
        """
        Scenario D: Opcode-Sensitive Generator (실험 6)
        - spray_execve 템플릿 사용
        - 가젯 친화적 바이트 패턴
        """
        print(f"\n{'='*60}")
        print(f"SCENARIO D: Opcode-Sensitive Generator ({count} functions)")
        print(f"{'='*60}")
        
        # spray_execve 템플릿을 사용하는 함수 생성
        print(f"[1/3] Generating opcode-sensitive functions...")
        
        def spray_execve(seed, buf):
            """가젯 친화적 opcode를 생성하는 템플릿"""
            helper = lambda v: (v ^ 0xC3C3C3C3) + 0x0F05FF90
            acc = seed
            for i in range(2048 + (seed & 0xFF)):
                acc ^= helper(acc) + (i << (i & 7))
                acc = ((acc << (i & 3)) | (acc >> (32 - (i & 3)))) & 0xFFFFFFFF
                acc += buf[i % len(buf)]
                if i & 1:
                    acc ^= buf[(i * 3) % len(buf)]
                else:
                    acc += helper(buf[(i * 5) % len(buf)])
            return acc
        
        # 이 템플릿을 여러 시드/버퍼로 실행하여 JIT 코드 생성
        functions = []
        for seed in range(count):
            buf = bytes(range(256))  # 고정 버퍼
            result = spray_execve(seed, buf)
            functions.append((seed, result))
        
        # 실제로는 이 함수들이 JIT 컴파일되도록 워밍업 필요
        print(f"[2/3] Warming up opcode-sensitive functions...")
        total_iters = int(iters)
        chunk = 200
        done = 0
        gc_disable_prev = gc.isenabled()
        try:
            gc.disable()
            while done < total_iters:
                step = min(chunk, total_iters - done)
                for _ in range(step):
                    for seed in range(min(10, count)):
                        buf = bytes(range(256))
                        spray_execve(seed, buf)
                done += step
                percent = int(done / total_iters * 100)
                if percent % 5 == 0:
                    print(f"    - Warmup progress: {percent}% ({done}/{total_iters})", flush=True)
        finally:
            if gc_disable_prev:
                gc.enable()
        
        print(f"[3/3] Scanning memory...")
        scanner = RuntimeJITScanner()
        memory_data = scanner.scan_memory()
        
        capture_data = {
            'scenario': scenario_name,
            'function_count': count,
            'template': 'spray_execve',
            'memory_data': memory_data
        }
        
        output_file = self.output_dir / f"{scenario_name}.pkl"
        with open(output_file, 'wb') as f:
            pickle.dump(capture_data, f)
        
        meta_file = self.output_dir / f"{scenario_name}_meta.json"
        with open(meta_file, 'w') as f:
            json.dump({
                'scenario': scenario_name,
                'function_count': count,
                'template': 'spray_execve',
                'regions': len(memory_data.get('regions', [])),
                'warmup_iterations': total_iters
            }, f, indent=2)
        
        print(f"\n✓ Captured data saved to: {output_file}")
        return capture_data


def main():
    """각 시나리오별 JIT 코드 생성 및 캡처"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate and capture JIT code for experiments')
    parser.add_argument('--scenario', choices=['a', 'b', 'c', 'd', 'all'], default='all',
                       help='Which scenario to generate (default: all)')
    parser.add_argument('--output-dir', default='gadget_analysis/jit_captures',
                       help='Output directory for captured data')
    parser.add_argument('--iters', type=int, default=6000,
                       help='Warmup iterations per function/template (default: 6000)')
    parser.add_argument('--count', type=int, default=None,
                       help='Function count for scenarios A/C/D (overrides defaults)')
    parser.add_argument('--regions', type=str, default=None,
                       help='Comma-separated region counts for scenario B (e.g., 1,8,16,32,64,80)')
    parser.add_argument('--repeat', type=int, default=1,
                       help='Repeat capture n times (scenario A only, default: 1)')
    args = parser.parse_args()
    
    capturer = JITCodeCapture(output_dir=args.output_dir)
    
    if args.scenario in ['a', 'all']:
        count = args.count if args.count is not None else 100
        capturer.capture_standard_functions(count=count, iters=args.iters, repeat=args.repeat, scenario_name='scenario_a')
    
    if args.scenario in ['b', 'all']:
        region_counts = [int(x) for x in (args.regions.split(',') if args.regions else ['1','8','16','32','64','80'])]
        capturer.capture_memory_scaling(region_counts=region_counts, iters=args.iters, scenario_name='scenario_b')
    
    if args.scenario in ['c', 'all']:
        count_c = args.count if args.count is not None else 50
        capturer.capture_syscall_taxonomy(count=count_c, iters=args.iters, scenario_name='scenario_c')
    
    if args.scenario in ['d', 'all']:
        count_d = args.count if args.count is not None else 50
        capturer.capture_opcode_sensitive(count=count_d, iters=args.iters, scenario_name='scenario_d')
    
    print(f"\n{'='*60}")
    print("All scenarios captured successfully!")
    print(f"Data saved to: {args.output_dir}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
