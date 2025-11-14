#!/usr/bin/env python3
"""
EXPERIMENT 3: Patch Function Impact Analysis
Scenario A 데이터를 재사용하여 patch_* 호출이 가젯에 미치는 영향 분석
"""
import json
from pathlib import Path
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

from gadget_analysis.jit_data_loader import JITDataLoader


def extract_patch_events(scenario_data):
    """
    패치 이벤트 추출 (실제로는 emitter가 로깅해야 함)
    여기서는 pre/post 메모리 비교로 추정
    """
    pre_patch = scenario_data.get('pre_patch', {})
    post_patch = scenario_data.get('post_patch', {})
    
    patch_events = []
    
    # 간단한 추정: 각 region의 바이트 변경 탐지
    pre_regions = {r.get('address', 0): r for r in pre_patch.get('regions', [])}
    post_regions = {r.get('address', 0): r for r in post_patch.get('regions', [])}
    
    for addr, post_region in post_regions.items():
        if addr in pre_regions:
            pre_region = pre_regions[addr]
            
            pre_bytes = pre_region.get('code', b'')
            post_bytes = post_region.get('code', b'')
            
            if pre_bytes != post_bytes:
                # 변경 탐지
                patch_events.append({
                    'address': addr,
                    'offset': 0,  # 실제로는 정확한 오프셋 필요
                    'pre_bytes': pre_bytes[:16].hex(),
                    'post_bytes': post_bytes[:16].hex(),
                    'patch_function': 'patch_unknown',  # 실제로는 로그에서 추출
                    'pre_gadget_count': len(pre_region.get('gadgets', [])),
                    'post_gadget_count': len(post_region.get('gadgets', []))
                })
    
    return patch_events


def analyze_patch_impact(patch_events):
    """패치 함수별 영향 분석"""
    impact_by_function = defaultdict(lambda: {
        'count': 0,
        'total_new_gadgets': 0,
        'events': []
    })
    
    for event in patch_events:
        func = event['patch_function']
        new_gadgets = event['post_gadget_count'] - event['pre_gadget_count']
        
        impact_by_function[func]['count'] += 1
        impact_by_function[func]['total_new_gadgets'] += new_gadgets
        impact_by_function[func]['events'].append(event)
    
    return dict(impact_by_function)


def create_scatter_plot(patch_events, output_file):
    """오프셋 vs 새 가젯 수 산점도"""
    offsets = [e['offset'] for e in patch_events]
    new_gadgets = [e['post_gadget_count'] - e['pre_gadget_count'] for e in patch_events]
    functions = [e['patch_function'] for e in patch_events]
    
    # 함수별 색상
    unique_funcs = list(set(functions))
    colors = plt.cm.tab10(np.linspace(0, 1, len(unique_funcs)))
    func_to_color = {func: colors[i] for i, func in enumerate(unique_funcs)}
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    for func in unique_funcs:
        mask = [f == func for f in functions]
        x = [offsets[i] for i, m in enumerate(mask) if m]
        y = [new_gadgets[i] for i, m in enumerate(mask) if m]
        ax.scatter(x, y, c=[func_to_color[func]], label=func, alpha=0.6, s=100)
    
    ax.set_xlabel('Patch Offset', fontsize=12)
    ax.set_ylabel('New Gadgets Introduced', fontsize=12)
    ax.set_title('Patch Function Impact on Gadget Generation', fontsize=14, fontweight='bold')
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Scatter plot saved: {output_file}")


def create_summary_table(impact_by_function, output_file):
    """패치 함수별 요약 테이블"""
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("EXPERIMENT 3: PATCH FUNCTION IMPACT SUMMARY\n")
        f.write("="*80 + "\n\n")
        
        f.write("Patch Function Statistics:\n")
        f.write("-"*80 + "\n")
        f.write(f"{'Function':<30} {'Invocations':>12} {'New Gadgets':>15} {'Avg/Call':>12}\n")
        f.write("-"*80 + "\n")
        
        sorted_funcs = sorted(impact_by_function.items(), 
                             key=lambda x: x[1]['total_new_gadgets'], 
                             reverse=True)
        
        for func, data in sorted_funcs:
            count = data['count']
            total = data['total_new_gadgets']
            avg = total / count if count > 0 else 0
            
            f.write(f"{func:<30} {count:>12} {total:>15} {avg:>12.1f}\n")
        
        f.write("-"*80 + "\n\n")
        
        f.write("Top 3 Highest-Impact Patches (by single-call gadget increase):\n")
        f.write("-"*80 + "\n")
        
        all_events = []
        for func, data in impact_by_function.items():
            for event in data['events']:
                event['function'] = func
                all_events.append(event)
        
        sorted_events = sorted(all_events, 
                              key=lambda e: e['post_gadget_count'] - e['pre_gadget_count'],
                              reverse=True)
        
        for i, event in enumerate(sorted_events[:3], 1):
            new_gadgets = event['post_gadget_count'] - event['pre_gadget_count']
            f.write(f"\n{i}. {event['function']} at offset {event['offset']}\n")
            f.write(f"   Address: {event['address']}\n")
            f.write(f"   New gadgets: {new_gadgets}\n")
            f.write(f"   Pre:  {event['pre_bytes']}\n")
            f.write(f"   Post: {event['post_bytes']}\n")
    
    print(f"✓ Summary table saved: {output_file}")


def create_bar_chart(impact_by_function, output_file):
    """패치 함수별 새 가젯 수 막대 차트"""
    functions = sorted(impact_by_function.keys(), 
                      key=lambda f: impact_by_function[f]['total_new_gadgets'],
                      reverse=True)
    
    new_gadgets = [impact_by_function[f]['total_new_gadgets'] for f in functions]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars = ax.barh(functions, new_gadgets, color='steelblue', alpha=0.7)
    
    ax.set_xlabel('Total New Gadgets', fontsize=12)
    ax.set_ylabel('Patch Function', fontsize=12)
    ax.set_title('New Gadgets Introduced by Patch Function', fontsize=14, fontweight='bold')
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Bar chart saved: {output_file}")


def main():
    print("="*60)
    print("EXPERIMENT 3: PATCH FUNCTION IMPACT ANALYSIS")
    print("Using Scenario A data (shared with Experiments 1 & 2)")
    print("="*60)
    
    output_dir = Path("gadget_analysis/experiment_3_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 데이터 로드
    print("\n[1/5] Loading Scenario A data...")
    loader = JITDataLoader()
    
    try:
        scenario_data = loader.load_scenario('scenario_a')
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease generate JIT code first:")
        print("  python3 gadget_analysis/jit_code_generator.py --scenario a")
        return 1
    
    # 2. 패치 이벤트 추출
    print("[2/5] Extracting patch events...")
    patch_events = extract_patch_events(scenario_data)
    
    if not patch_events:
        print("⚠ No patch events found (pre/post memory identical)")
        print("  Note: Real implementation needs emitter instrumentation")
    
    # 3. 영향 분석
    print("[3/5] Analyzing patch function impact...")
    impact_by_function = analyze_patch_impact(patch_events)
    
    # 4. 시각화
    print("[4/5] Generating visualizations...")
    if patch_events:
        create_scatter_plot(patch_events, output_dir / "patch_impact_scatter.png")
        create_bar_chart(impact_by_function, output_dir / "patch_impact_bars.png")
    
    # 5. 보고서
    print("[5/5] Generating report...")
    create_summary_table(impact_by_function, output_dir / "summary.txt")
    
    # JSON 저장
    with open(output_dir / "patch_events.json", 'w') as f:
        json.dump({
            'patch_events': patch_events,
            'impact_by_function': impact_by_function
        }, f, indent=2)
    
    print("\n" + "="*60)
    print("✓ EXPERIMENT 3 COMPLETED")
    print(f"✓ Results saved to: {output_dir}")
    print("="*60)
    
    print(f"\nNote: For accurate patch tracking, instrument the emitter to log:")
    print(f"  - patch_* function names")
    print(f"  - target offsets")
    print(f"  - pre/post bytes at each call")


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
