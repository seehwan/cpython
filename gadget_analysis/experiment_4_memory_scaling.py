#!/usr/bin/env python3
"""
EXPERIMENT 4: Executor Memory Scaling Analysis
Scenario B 데이터를 사용하여 메모리 영역 확장에 따른 가젯 증가 분석
"""
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

from gadget_analysis.jit_data_loader import JITDataLoader
from gadget_analysis.classifier import GadgetClassifier


def analyze_region_gadgets(captures):
    """각 region count별 가젯 통계 추출"""
    results = []
    
    for capture in captures:
        region_count = capture['region_count']
        memory_data = capture['memory_data']
        regions = memory_data.get('regions', [])
        
        total_gadgets = 0
        gadget_addresses = []
        
        for region in regions:
            gadgets = region.get('gadgets', [])
            total_gadgets += len(gadgets)
            
            for gadget in gadgets:
                gadget_addresses.append(gadget.get('address', 0))
        
        results.append({
            'region_count': region_count,
            'total_gadgets': total_gadgets,
            'gadgets_per_region': total_gadgets / max(region_count, 1),
            'addresses': gadget_addresses
        })
    
    return results


def fit_linear_trend(results):
    """가젯 수 증가 추세 선형 회귀"""
    x = np.array([r['region_count'] for r in results])
    y = np.array([r['total_gadgets'] for r in results])
    
    # 선형 회귀
    slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
    
    # 신뢰구간 (95%)
    predict_y = slope * x + intercept
    residuals = y - predict_y
    se = np.sqrt(np.sum(residuals**2) / (len(x) - 2))
    
    # t-분포 기반 신뢰구간
    from scipy.stats import t
    t_val = t.ppf(0.975, len(x) - 2)
    margin = t_val * se * np.sqrt(1/len(x) + (x - np.mean(x))**2 / np.sum((x - np.mean(x))**2))
    
    return {
        'slope': slope,
        'intercept': intercept,
        'r_squared': r_value**2,
        'p_value': p_value,
        'std_err': std_err,
        'confidence_intervals': list(zip(predict_y - margin, predict_y + margin))
    }


def create_scaling_plot(results, trend, output_file):
    """메모리 스케일링 그래프 (신뢰구간 포함)"""
    x = np.array([r['region_count'] for r in results])
    y = np.array([r['total_gadgets'] for r in results])
    
    # 예측선
    x_line = np.linspace(x.min(), x.max(), 100)
    y_line = trend['slope'] * x_line + trend['intercept']
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 실제 데이터
    ax.scatter(x, y, s=100, alpha=0.6, color='steelblue', label='Observed', zorder=3)
    
    # 회귀선
    ax.plot(x_line, y_line, 'r--', linewidth=2, label=f'Linear Fit (R²={trend["r_squared"]:.3f})', zorder=2)
    
    # 신뢰구간
    ci = trend['confidence_intervals']
    ci_lower = [c[0] for c in ci]
    ci_upper = [c[1] for c in ci]
    ax.fill_between(x, ci_lower, ci_upper, alpha=0.2, color='red', label='95% CI')
    
    ax.set_xlabel('Number of JIT Regions', fontsize=12)
    ax.set_ylabel('Total Gadget Count', fontsize=12)
    ax.set_title('Executor Memory Scaling: Gadgets vs. Region Count', fontsize=14, fontweight='bold')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # 추세 정보 텍스트
    textstr = f'y = {trend["slope"]:.2f}x + {trend["intercept"]:.2f}\n'
    textstr += f'p-value: {trend["p_value"]:.2e}'
    ax.text(0.05, 0.95, textstr, transform=ax.transAxes, 
            fontsize=10, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Scaling plot saved: {output_file}")


def create_violin_plot(results, output_file):
    """가젯 오프셋 분포 바이올린 플롯"""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    data_to_plot = []
    labels = []
    
    for result in results:
        region_count = result['region_count']
        addresses = result['addresses']
        
        if not addresses:
            continue
        
        # 베이스 주소로 정규화 (상대 오프셋)
        base_addr = min(addresses)
        normalized_offsets = [(addr - base_addr) / 1024 for addr in addresses]  # KB 단위
        
        data_to_plot.append(normalized_offsets)
        labels.append(f'{region_count} regions')
    
    if data_to_plot:
        parts = ax.violinplot(data_to_plot, positions=range(len(data_to_plot)), 
                              showmeans=True, showmedians=True)
        
        # 색상 설정
        for pc in parts['bodies']:
            pc.set_facecolor('lightblue')
            pc.set_alpha(0.7)
        
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45)
        ax.set_ylabel('Normalized Gadget Offset (KB)', fontsize=12)
        ax.set_xlabel('Configuration', fontsize=12)
        ax.set_title('Gadget Distribution Across Memory Regions', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Violin plot saved: {output_file}")


def create_per_region_chart(results, output_file):
    """영역당 평균 가젯 수 차트"""
    x = [r['region_count'] for r in results]
    y = [r['gadgets_per_region'] for r in results]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    ax.plot(x, y, 'o-', linewidth=2, markersize=8, color='darkgreen')
    
    ax.set_xlabel('Number of JIT Regions', fontsize=12)
    ax.set_ylabel('Gadgets per Region (average)', fontsize=12)
    ax.set_title('Average Gadget Density per Region', fontsize=14, fontweight='bold')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Per-region chart saved: {output_file}")


def generate_report(results, trend, output_file):
    """실험 4 보고서 생성"""
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("EXPERIMENT 4: EXECUTOR MEMORY SCALING ANALYSIS\n")
        f.write("="*80 + "\n\n")
        
        f.write("Methodology:\n")
        f.write("  - Allocated varying numbers of JIT regions (1, 8, 32, 80 × 128KB)\n")
        f.write("  - Measured gadget counts for each configuration\n")
        f.write("  - Fitted linear trend with 95% confidence intervals\n\n")
        
        f.write("Results:\n")
        f.write("-"*80 + "\n")
        f.write(f"{'Regions':>10} {'Total Gadgets':>15} {'Per Region':>15} {'95% CI Range':>20}\n")
        f.write("-"*80 + "\n")
        
        for i, result in enumerate(results):
            region_count = result['region_count']
            total = result['total_gadgets']
            per_region = result['gadgets_per_region']
            
            ci = trend['confidence_intervals'][i]
            ci_str = f"[{ci[0]:.0f}, {ci[1]:.0f}]"
            
            f.write(f"{region_count:>10} {total:>15} {per_region:>15.1f} {ci_str:>20}\n")
        
        f.write("-"*80 + "\n\n")
        
        f.write("Linear Regression Analysis:\n")
        f.write(f"  Equation: y = {trend['slope']:.2f}x + {trend['intercept']:.2f}\n")
        f.write(f"  R-squared: {trend['r_squared']:.4f}\n")
        f.write(f"  p-value: {trend['p_value']:.2e}\n")
        f.write(f"  Standard Error: {trend['std_err']:.2f}\n\n")
        
        if trend['r_squared'] > 0.95:
            f.write("  ✓ Strong linear relationship (R² > 0.95)\n")
        elif trend['r_squared'] > 0.85:
            f.write("  ✓ Moderate linear relationship (R² > 0.85)\n")
        else:
            f.write("  ⚠ Weak linear relationship - possible saturation or non-linearity\n")
        
        f.write("\n")
        f.write("Key Observations:\n")
        f.write("-"*80 + "\n")
        
        # 포화 지점 추정
        if len(results) > 2:
            growth_rates = []
            for i in range(1, len(results)):
                prev = results[i-1]['total_gadgets']
                curr = results[i]['total_gadgets']
                growth = (curr - prev) / prev * 100 if prev > 0 else 0
                growth_rates.append(growth)
            
            avg_growth = np.mean(growth_rates)
            f.write(f"  - Average growth rate: {avg_growth:.1f}% per region increase\n")
            
            # 포화 감지
            if len(growth_rates) > 1 and growth_rates[-1] < growth_rates[0] * 0.5:
                f.write("  - ⚠ Saturation detected: growth rate declining\n")
            else:
                f.write("  - Linear growth continues (no saturation observed)\n")
        
        f.write(f"  - Slope indicates ~{trend['slope']:.0f} new gadgets per additional region\n")
    
    print(f"✓ Report saved: {output_file}")


def main():
    print("="*60)
    print("EXPERIMENT 4: EXECUTOR MEMORY SCALING ANALYSIS")
    print("Using Scenario B data (multi-region allocation)")
    print("="*60)
    
    output_dir = Path("gadget_analysis/experiment_4_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 데이터 로드
    print("\n[1/6] Loading Scenario B data...")
    loader = JITDataLoader()
    
    try:
        captures = loader.load_scenario('scenario_b')
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease generate JIT code first:")
        print("  python3 gadget_analysis/jit_code_generator.py --scenario b")
        return 1
    
    # 2. 가젯 분석
    print("[2/6] Analyzing gadgets across region counts...")
    results = analyze_region_gadgets(captures)
    
    # 3. 추세 분석
    print("[3/6] Fitting linear trend...")
    trend = fit_linear_trend(results)
    
    # 4. 시각화
    print("[4/6] Generating scaling plot...")
    create_scaling_plot(results, trend, output_dir / "scaling_plot.png")
    
    print("[5/6] Generating violin plot...")
    create_violin_plot(results, output_dir / "gadget_distribution_violin.png")
    
    create_per_region_chart(results, output_dir / "per_region_density.png")
    
    # 5. 보고서
    print("[6/6] Generating report...")
    generate_report(results, trend, output_dir / "report.txt")
    
    # JSON 저장
    with open(output_dir / "scaling_data.json", 'w') as f:
        json.dump({
            'results': results,
            'trend': {k: v for k, v in trend.items() if k != 'confidence_intervals'},
            'trend_equation': f"y = {trend['slope']:.2f}x + {trend['intercept']:.2f}"
        }, f, indent=2)
    
    print("\n" + "="*60)
    print("✓ EXPERIMENT 4 COMPLETED")
    print(f"✓ Results saved to: {output_dir}")
    print("="*60)
    
    print(f"\nLinear Fit: y = {trend['slope']:.2f}x + {trend['intercept']:.2f}")
    print(f"R² = {trend['r_squared']:.4f}")


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
