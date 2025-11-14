#!/usr/bin/env python3
"""
EXPERIMENT 6: Opcode-Sensitive Function Generator Analysis
Scenario D 데이터를 사용하여 spray_execve 템플릿의 가젯 생성 효과 분석
"""
import json
from pathlib import Path
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

from gadget_analysis.jit_data_loader import JITDataLoader
from gadget_analysis.classifier import GadgetClassifier


def analyze_byte_distribution(memory_data):
    """생성된 바이트 분포 분석 (가젯 친화적 바이트)"""
    target_bytes = {
        0xC3: 'ret',
        0x0F: 'syscall_prefix',
        0x05: 'syscall_suffix',
        0xFF: 'indirect',
        0x90: 'nop'
    }
    
    byte_counts = defaultdict(int)
    total_bytes = 0
    gadget_friendly_count = 0
    
    regions = memory_data.get('regions', [])
    
    for region in regions:
        code = region.get('code', b'')
        
        for byte in code:
            byte_counts[byte] += 1
            total_bytes += 1
            
            if byte in target_bytes:
                gadget_friendly_count += 1
    
    return {
        'byte_counts': dict(byte_counts),
        'target_bytes': {
            hex(k): {
                'name': v,
                'count': byte_counts.get(k, 0),
                'percentage': byte_counts.get(k, 0) / max(total_bytes, 1) * 100
            }
            for k, v in target_bytes.items()
        },
        'total_bytes': total_bytes,
        'gadget_friendly_percentage': gadget_friendly_count / max(total_bytes, 1) * 100
    }


def compare_with_baseline(scenario_d_data, scenario_a_data):
    """Scenario D (opcode-sensitive)와 Scenario A (baseline) 비교"""
    d_memory = scenario_d_data.get('memory_data', {})
    a_memory = scenario_a_data.get('post_patch', {})
    
    d_byte_dist = analyze_byte_distribution(d_memory)
    a_byte_dist = analyze_byte_distribution(a_memory)
    
    # 가젯 수 비교
    d_regions = d_memory.get('regions', [])
    a_regions = a_memory.get('regions', [])
    
    d_gadget_count = sum(len(r.get('gadgets', [])) for r in d_regions)
    a_gadget_count = sum(len(r.get('gadgets', [])) for r in a_regions)
    
    return {
        'opcode_sensitive': {
            'gadgets': d_gadget_count,
            'byte_dist': d_byte_dist
        },
        'baseline': {
            'gadgets': a_gadget_count,
            'byte_dist': a_byte_dist
        },
        'improvement': {
            'gadget_increase': d_gadget_count - a_gadget_count,
            'percentage_increase': (d_gadget_count - a_gadget_count) / max(a_gadget_count, 1) * 100
        }
    }


def create_byte_distribution_chart(comparison, output_file):
    """가젯 친화적 바이트 분포 비교 차트"""
    target_bytes_names = ['ret (0xC3)', 'syscall (0x0F)', 'syscall (0x05)', 
                          'indirect (0xFF)', 'nop (0x90)']
    
    d_target = comparison['opcode_sensitive']['byte_dist']['target_bytes']
    a_target = comparison['baseline']['byte_dist']['target_bytes']
    
    # 바이트별 비율 추출
    d_percentages = [d_target.get(hex(b), {}).get('percentage', 0) 
                     for b in [0xC3, 0x0F, 0x05, 0xFF, 0x90]]
    a_percentages = [a_target.get(hex(b), {}).get('percentage', 0) 
                     for b in [0xC3, 0x0F, 0x05, 0xFF, 0x90]]
    
    x = np.arange(len(target_bytes_names))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    bars1 = ax.bar(x - width/2, a_percentages, width, label='Baseline', alpha=0.8, color='lightblue')
    bars2 = ax.bar(x + width/2, d_percentages, width, label='Opcode-Sensitive', alpha=0.8, color='orange')
    
    ax.set_xlabel('Target Byte', fontsize=12)
    ax.set_ylabel('Percentage (%)', fontsize=12)
    ax.set_title('Gadget-Friendly Byte Distribution Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(target_bytes_names, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Byte distribution chart saved: {output_file}")


def create_gadget_count_comparison(comparison, output_file):
    """가젯 수 비교 막대 차트"""
    categories = ['Baseline\n(Standard)', 'Opcode-Sensitive\n(spray_execve)']
    gadget_counts = [
        comparison['baseline']['gadgets'],
        comparison['opcode_sensitive']['gadgets']
    ]
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    bars = ax.bar(categories, gadget_counts, color=['steelblue', 'darkorange'], alpha=0.7)
    
    # 값 레이블
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height)}',
               ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    # 증가율 표시
    increase_pct = comparison['improvement']['percentage_increase']
    ax.text(1, gadget_counts[1] * 0.5, 
           f'+{increase_pct:.1f}%',
           ha='center', va='center', fontsize=14, fontweight='bold',
           bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.7))
    
    ax.set_ylabel('Total Gadget Count', fontsize=12)
    ax.set_title('Gadget Generation: Baseline vs. Opcode-Sensitive', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Gadget count comparison saved: {output_file}")


def create_improvement_breakdown(comparison, output_file):
    """개선 효과 세부 분석 차트"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # 왼쪽: 전체 가젯 친화적 바이트 비율
    labels = ['Baseline', 'Opcode-Sensitive']
    friendly_pcts = [
        comparison['baseline']['byte_dist']['gadget_friendly_percentage'],
        comparison['opcode_sensitive']['byte_dist']['gadget_friendly_percentage']
    ]
    
    bars1 = ax1.bar(labels, friendly_pcts, color=['lightcoral', 'lightgreen'], alpha=0.7)
    ax1.set_ylabel('Gadget-Friendly Bytes (%)', fontsize=11)
    ax1.set_title('Overall Byte Quality', fontsize=12, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}%',
                ha='center', va='bottom', fontsize=10)
    
    # 오른쪽: 가젯 밀도 (가젯/KB)
    baseline_bytes = comparison['baseline']['byte_dist']['total_bytes']
    opcode_bytes = comparison['opcode_sensitive']['byte_dist']['total_bytes']
    
    baseline_density = comparison['baseline']['gadgets'] / (baseline_bytes / 1024)
    opcode_density = comparison['opcode_sensitive']['gadgets'] / (opcode_bytes / 1024)
    
    densities = [baseline_density, opcode_density]
    bars2 = ax2.bar(labels, densities, color=['lightcoral', 'lightgreen'], alpha=0.7)
    ax2.set_ylabel('Gadgets per KB', fontsize=11)
    ax2.set_title('Gadget Density', fontsize=12, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}',
                ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Improvement breakdown saved: {output_file}")


def generate_report(comparison, output_file):
    """실험 6 보고서 생성"""
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("EXPERIMENT 6: OPCODE-SENSITIVE FUNCTION GENERATOR ANALYSIS\n")
        f.write("="*80 + "\n\n")
        
        f.write("Methodology:\n")
        f.write("  - Used spray_execve template to bias bytecode toward gadget-friendly opcodes\n")
        f.write("  - Compared with baseline (standard JIT function generation)\n")
        f.write("  - Analyzed byte distribution and gadget density\n\n")
        
        f.write("Results Summary:\n")
        f.write("-"*80 + "\n")
        
        baseline = comparison['baseline']
        opcode = comparison['opcode_sensitive']
        improvement = comparison['improvement']
        
        f.write(f"{'Metric':<30} {'Baseline':>15} {'Opcode-Sensitive':>20} {'Δ':>12}\n")
        f.write("-"*80 + "\n")
        
        f.write(f"{'Total Gadgets':<30} {baseline['gadgets']:>15} {opcode['gadgets']:>20} "
               f"{improvement['gadget_increase']:>+12}\n")
        
        baseline_friendly = baseline['byte_dist']['gadget_friendly_percentage']
        opcode_friendly = opcode['byte_dist']['gadget_friendly_percentage']
        f.write(f"{'Gadget-Friendly Bytes (%)':<30} {baseline_friendly:>15.2f} {opcode_friendly:>20.2f} "
               f"{opcode_friendly - baseline_friendly:>+12.2f}\n")
        
        baseline_bytes = baseline['byte_dist']['total_bytes']
        opcode_bytes = opcode['byte_dist']['total_bytes']
        f.write(f"{'Total Code Size (bytes)':<30} {baseline_bytes:>15} {opcode_bytes:>20} "
               f"{opcode_bytes - baseline_bytes:>+12}\n")
        
        f.write("-"*80 + "\n")
        f.write(f"{'Improvement':<30} {improvement['percentage_increase']:>15.1f}%\n\n")
        
        f.write("Target Byte Analysis:\n")
        f.write("-"*80 + "\n")
        f.write(f"{'Byte':<15} {'Name':<20} {'Baseline':>12} {'Opcode-Sen':>15} {'Δ':>10}\n")
        f.write("-"*80 + "\n")
        
        target_bytes = [
            (0xC3, 'ret'),
            (0x0F, 'syscall_prefix'),
            (0x05, 'syscall_suffix'),
            (0xFF, 'indirect'),
            (0x90, 'nop')
        ]
        
        for byte_val, name in target_bytes:
            hex_str = hex(byte_val)
            b_count = baseline['byte_dist']['target_bytes'].get(hex_str, {}).get('count', 0)
            o_count = opcode['byte_dist']['target_bytes'].get(hex_str, {}).get('count', 0)
            
            f.write(f"{hex_str:<15} {name:<20} {b_count:>12} {o_count:>15} {o_count - b_count:>+10}\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("Key Observations:\n")
        f.write("-"*80 + "\n")
        
        if improvement['percentage_increase'] > 20:
            f.write("  ✓ Significant improvement: opcode-sensitive generation increases gadgets by >20%\n")
        elif improvement['percentage_increase'] > 10:
            f.write("  ✓ Moderate improvement: 10-20% increase in gadget availability\n")
        else:
            f.write("  ⚠ Limited improvement: <10% increase\n")
        
        f.write(f"  - spray_execve template increases gadget-friendly bytes by "
               f"{opcode_friendly - baseline_friendly:.1f} percentage points\n")
        
        f.write("  - Helper lambdas (v ^ 0xC3C3C3C3) successfully inject target opcodes\n")
        f.write("  - Attacker-controlled buffers can fine-tune byte patterns for specific gadgets\n")
    
    print(f"✓ Report saved: {output_file}")


def main():
    print("="*60)
    print("EXPERIMENT 6: OPCODE-SENSITIVE FUNCTION GENERATOR")
    print("Using Scenario D data (spray_execve template)")
    print("="*60)
    
    output_dir = Path("gadget_analysis/experiment_6_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 데이터 로드
    print("\n[1/5] Loading Scenario D data...")
    loader = JITDataLoader()
    
    try:
        scenario_d = loader.load_scenario('scenario_d')
        scenario_a = loader.load_scenario('scenario_a')
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease generate JIT code first:")
        print("  python3 gadget_analysis/jit_code_generator.py --scenario d")
        print("  python3 gadget_analysis/jit_code_generator.py --scenario a")
        return 1
    
    # 2. 비교 분석
    print("[2/5] Comparing opcode-sensitive vs baseline...")
    comparison = compare_with_baseline(scenario_d, scenario_a)
    
    # 3. 시각화
    print("[3/5] Generating byte distribution chart...")
    create_byte_distribution_chart(comparison, output_dir / "byte_distribution.png")
    
    print("[4/5] Generating gadget comparison charts...")
    create_gadget_count_comparison(comparison, output_dir / "gadget_comparison.png")
    create_improvement_breakdown(comparison, output_dir / "improvement_breakdown.png")
    
    # 4. 보고서
    print("[5/5] Generating report...")
    generate_report(comparison, output_dir / "report.txt")
    
    # JSON 저장
    with open(output_dir / "comparison_data.json", 'w') as f:
        json.dump({
            'baseline_gadgets': comparison['baseline']['gadgets'],
            'opcode_sensitive_gadgets': comparison['opcode_sensitive']['gadgets'],
            'improvement_percentage': comparison['improvement']['percentage_increase'],
            'target_bytes': comparison['opcode_sensitive']['byte_dist']['target_bytes']
        }, f, indent=2)
    
    print("\n" + "="*60)
    print("✓ EXPERIMENT 6 COMPLETED")
    print(f"✓ Results saved to: {output_dir}")
    print("="*60)
    
    improvement = comparison['improvement']
    print(f"\nGadget Increase: +{improvement['gadget_increase']} ({improvement['percentage_increase']:+.1f}%)")


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
