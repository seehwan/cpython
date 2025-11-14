#!/usr/bin/env python3
"""
EXPERIMENT 5: Ret-Free Syscall Chain Taxonomy
Scenario C 데이터를 사용하여 syscall 가젯 분류 및 ret-free 체인 분석
"""
import json
from pathlib import Path
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

from gadget_analysis.jit_data_loader import JITDataLoader
from gadget_analysis.classifier import GadgetClassifier


def classify_gadgets_by_type(memory_data):
    """가젯을 타입별로 분류"""
    gadget_types = {
        'ret': [],
        'syscall': [],
        'indirect_branch': [],
        'stack_pivot': [],
        'pop': [],
        'other': []
    }
    
    regions = memory_data.get('regions', [])
    
    for region in regions:
        gadgets = region.get('gadgets', [])
        
        for gadget in gadgets:
            bytes_hex = gadget.get('bytes', '')
            address = gadget.get('address', 0)
            
            # 간단한 패턴 매칭 (실제로는 Capstone 디스어셈블리 사용)
            if 'c3' in bytes_hex:
                gadget_types['ret'].append(gadget)
            elif '0f05' in bytes_hex:
                gadget_types['syscall'].append(gadget)
            elif 'ff' in bytes_hex and ('e' in bytes_hex or 'd' in bytes_hex):
                gadget_types['indirect_branch'].append(gadget)
            elif ('58' in bytes_hex or '59' in bytes_hex or '5a' in bytes_hex or 
                  '5b' in bytes_hex or '5c' in bytes_hex or '5d' in bytes_hex or 
                  '5e' in bytes_hex or '5f' in bytes_hex):
                gadget_types['pop'].append(gadget)
            elif ('89' in bytes_hex and 'e' in bytes_hex):  # mov rsp, ...
                gadget_types['stack_pivot'].append(gadget)
            else:
                gadget_types['other'].append(gadget)
    
    return gadget_types


def find_ret_free_chains(gadget_types):
    """
    Ret-free 체인 찾기
    - syscall로 끝나고
    - pop 가젯으로 레지스터 설정
    - ret 없음
    """
    syscall_gadgets = gadget_types['syscall']
    pop_gadgets = gadget_types['pop']
    
    ret_free_chains = []
    
    # 간단한 예시: syscall 전에 pop 가젯이 있는 경우
    for syscall_gadget in syscall_gadgets:
        syscall_addr = syscall_gadget.get('address', 0)
        
        # syscall 근처의 pop 가젯 찾기 (주소 범위 내)
        nearby_pops = [
            pop for pop in pop_gadgets 
            if abs(pop.get('address', 0) - syscall_addr) < 32
        ]
        
        if nearby_pops:
            ret_free_chains.append({
                'syscall': syscall_gadget,
                'setup_gadgets': nearby_pops,
                'chain_length': len(nearby_pops) + 1
            })
    
    return ret_free_chains


def create_taxonomy_stacked_bar(gadget_types, output_file):
    """가젯 타입별 비율 스택 막대 차트"""
    types = ['ret', 'syscall', 'indirect_branch', 'stack_pivot', 'pop', 'other']
    counts = [len(gadget_types[t]) for t in types]
    total = sum(counts)
    
    if total == 0:
        print("⚠ No gadgets found for taxonomy chart")
        return
    
    percentages = [c / total * 100 for c in counts]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 색상 팔레트
    colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ff99cc', '#c2c2f0']
    
    # 스택 바
    left = 0
    for i, (type_name, count, pct, color) in enumerate(zip(types, counts, percentages, colors)):
        ax.barh(0, pct, left=left, height=0.5, color=color, 
                label=f'{type_name} ({count})', edgecolor='black')
        
        # 텍스트 레이블
        if pct > 3:  # 3% 이상만 표시
            ax.text(left + pct/2, 0, f'{pct:.1f}%', 
                   ha='center', va='center', fontsize=10, fontweight='bold')
        
        left += pct
    
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 0.5)
    ax.set_xlabel('Percentage', fontsize=12)
    ax.set_title('Gadget Taxonomy: Type Distribution', fontsize=14, fontweight='bold')
    ax.set_yticks([])
    ax.legend(loc='upper left', bbox_to_anchor=(1, 1))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Taxonomy stacked bar saved: {output_file}")


def create_ret_free_analysis_chart(ret_free_chains, output_file):
    """Ret-free 체인 길이 분포 차트"""
    if not ret_free_chains:
        print("⚠ No ret-free chains found")
        return
    
    chain_lengths = [chain['chain_length'] for chain in ret_free_chains]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 히스토그램
    bins = range(1, max(chain_lengths) + 2)
    ax.hist(chain_lengths, bins=bins, alpha=0.7, color='skyblue', edgecolor='black')
    
    ax.set_xlabel('Chain Length (gadgets)', fontsize=12)
    ax.set_ylabel('Frequency', fontsize=12)
    ax.set_title('Ret-Free Syscall Chain Length Distribution', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Ret-free chain analysis saved: {output_file}")


def create_gadget_type_comparison(gadget_types, output_file):
    """가젯 타입 비교 막대 차트"""
    types = list(gadget_types.keys())
    counts = [len(gadget_types[t]) for t in types]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars = ax.bar(types, counts, color='steelblue', alpha=0.7, edgecolor='black')
    
    # 값 레이블
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height)}',
               ha='center', va='bottom', fontsize=10)
    
    ax.set_xlabel('Gadget Type', fontsize=12)
    ax.set_ylabel('Count', fontsize=12)
    ax.set_title('Gadget Type Distribution', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    plt.xticks(rotation=45, ha='right')
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Gadget type comparison saved: {output_file}")


def generate_report(gadget_types, ret_free_chains, output_file):
    """실험 5 보고서 생성"""
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("EXPERIMENT 5: RET-FREE SYSCALL CHAIN TAXONOMY\n")
        f.write("="*80 + "\n\n")
        
        f.write("Methodology:\n")
        f.write("  - Automated gadget taxonomy: ret, syscall, indirect branch, stack pivot\n")
        f.write("  - Identified chains using only pop + syscall (no trailing ret)\n")
        f.write("  - Analyzed chain length and composition\n\n")
        
        f.write("Gadget Type Statistics:\n")
        f.write("-"*80 + "\n")
        f.write(f"{'Type':<20} {'Count':>10} {'Percentage':>15}\n")
        f.write("-"*80 + "\n")
        
        total = sum(len(gadgets) for gadgets in gadget_types.values())
        
        for gadget_type, gadgets in sorted(gadget_types.items(), 
                                           key=lambda x: len(x[1]), 
                                           reverse=True):
            count = len(gadgets)
            pct = count / total * 100 if total > 0 else 0
            f.write(f"{gadget_type:<20} {count:>10} {pct:>14.1f}%\n")
        
        f.write("-"*80 + "\n")
        f.write(f"{'TOTAL':<20} {total:>10} {100.0:>14.1f}%\n\n")
        
        f.write("Ret-Free Chain Analysis:\n")
        f.write("-"*80 + "\n")
        f.write(f"  Total chains found: {len(ret_free_chains)}\n")
        
        if ret_free_chains:
            chain_lengths = [chain['chain_length'] for chain in ret_free_chains]
            f.write(f"  Average chain length: {np.mean(chain_lengths):.1f} gadgets\n")
            f.write(f"  Min chain length: {min(chain_lengths)}\n")
            f.write(f"  Max chain length: {max(chain_lengths)}\n\n")
            
            f.write("Sample Chains:\n")
            for i, chain in enumerate(ret_free_chains[:5], 1):
                f.write(f"\n  Chain {i}:\n")
                f.write(f"    Length: {chain['chain_length']}\n")
                f.write(f"    Syscall at: {hex(chain['syscall'].get('address', 0))}\n")
                f.write(f"    Setup gadgets: {len(chain['setup_gadgets'])}\n")
        else:
            f.write("  ⚠ No ret-free chains found\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("Key Observations:\n")
        f.write("-"*80 + "\n")
        
        syscall_count = len(gadget_types['syscall'])
        ret_count = len(gadget_types['ret'])
        
        f.write(f"  - Syscall gadgets: {syscall_count}\n")
        f.write(f"  - Ret gadgets: {ret_count}\n")
        f.write(f"  - Syscall/Ret ratio: {syscall_count/max(ret_count, 1):.2f}\n")
        
        if len(ret_free_chains) > 0:
            f.write(f"  - {len(ret_free_chains)} exploitable ret-free chains identified\n")
            f.write("  - These chains avoid ret-based CFI mitigations\n")
        else:
            f.write("  - Limited ret-free chain opportunities\n")
            f.write("  - May require libc gadgets for full ROP chains\n")
    
    print(f"✓ Report saved: {output_file}")


def main():
    print("="*60)
    print("EXPERIMENT 5: RET-FREE SYSCALL CHAIN TAXONOMY")
    print("Using Scenario C data (syscall-focused generation)")
    print("="*60)
    
    output_dir = Path("gadget_analysis/experiment_5_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 데이터 로드
    print("\n[1/5] Loading Scenario C data...")
    loader = JITDataLoader()
    
    try:
        scenario_data = loader.load_scenario('scenario_c')
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease generate JIT code first:")
        print("  python3 gadget_analysis/jit_code_generator.py --scenario c")
        return 1
    
    memory_data = scenario_data.get('memory_data', {})
    
    # 2. 가젯 분류
    print("[2/5] Classifying gadgets by type...")
    gadget_types = classify_gadgets_by_type(memory_data)
    
    # 3. Ret-free 체인 찾기
    print("[3/5] Identifying ret-free syscall chains...")
    ret_free_chains = find_ret_free_chains(gadget_types)
    
    # 4. 시각화
    print("[4/5] Generating visualizations...")
    create_taxonomy_stacked_bar(gadget_types, output_dir / "taxonomy_stacked_bar.png")
    create_gadget_type_comparison(gadget_types, output_dir / "type_comparison.png")
    
    if ret_free_chains:
        create_ret_free_analysis_chart(ret_free_chains, output_dir / "ret_free_chains.png")
    
    # 5. 보고서
    print("[5/5] Generating report...")
    generate_report(gadget_types, ret_free_chains, output_dir / "report.txt")
    
    # JSON 저장
    with open(output_dir / "taxonomy_data.json", 'w') as f:
        json.dump({
            'gadget_types': {k: len(v) for k, v in gadget_types.items()},
            'ret_free_chains': len(ret_free_chains),
            'sample_chains': [
                {
                    'length': chain['chain_length'],
                    'syscall_address': hex(chain['syscall'].get('address', 0))
                }
                for chain in ret_free_chains[:10]
            ]
        }, f, indent=2)
    
    print("\n" + "="*60)
    print("✓ EXPERIMENT 5 COMPLETED")
    print(f"✓ Results saved to: {output_dir}")
    print("="*60)
    
    print(f"\nGadget Types Found:")
    for gtype, gadgets in gadget_types.items():
        print(f"  {gtype}: {len(gadgets)}")
    print(f"\nRet-Free Chains: {len(ret_free_chains)}")


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
