#!/usr/bin/env python3
"""
EXPERIMENT 1: Stencil Gadget Cataloging (Refactored)
저장된 JIT 메모리 덤프를 사용하여 빠르게 분석
"""
import json
from pathlib import Path
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

from gadget_analysis.jit_data_loader import JITDataLoader
from gadget_analysis.classifier import GadgetClassifier


def analyze_memory_data(memory_data, classifier):
    """메모리 데이터에서 가젯 분석"""
    gadgets_by_stencil = defaultdict(lambda: defaultdict(int))
    all_gadgets = []
    
    regions = memory_data.get('regions', [])
    
    for region in regions:
        # 각 region은 스텐실 ID를 가져야 함 (스캐너 구현에 따라 다름)
        stencil_id = region.get('stencil_id', 'unknown')
        gadgets = region.get('gadgets', [])
        
        for gadget in gadgets:
            # 가젯 분류
            category = classifier.classify(gadget)
            gadgets_by_stencil[stencil_id][category] += 1
            all_gadgets.append({
                'stencil': stencil_id,
                'category': category,
                'bytes': gadget.get('bytes', ''),
                'address': gadget.get('address', 0)
            })
    
    return gadgets_by_stencil, all_gadgets


def create_catalog(pre_gadgets, post_gadgets, output_file):
    """가젯 카탈로그 JSON 생성"""
    catalog = {
        'pre_patch': {
            'by_stencil': dict(pre_gadgets),
            'total_stencils': len(pre_gadgets),
            'total_gadgets': sum(sum(cats.values()) for cats in pre_gadgets.values())
        },
        'post_patch': {
            'by_stencil': dict(post_gadgets),
            'total_stencils': len(post_gadgets),
            'total_gadgets': sum(sum(cats.values()) for cats in post_gadgets.values())
        },
        'new_gadgets': {
            'count': sum(sum(cats.values()) for cats in post_gadgets.values()) - 
                     sum(sum(cats.values()) for cats in pre_gadgets.values())
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(catalog, f, indent=2)
    
    print(f"✓ Catalog saved: {output_file}")
    return catalog


def create_heatmap(gadgets_by_stencil, output_file, title="Gadget Heatmap"):
    """스텐실 × 가젯 카테고리 히트맵"""
    # 모든 카테고리 수집
    all_categories = set()
    for cats in gadgets_by_stencil.values():
        all_categories.update(cats.keys())
    
    all_categories = sorted(all_categories)
    stencils = sorted(gadgets_by_stencil.keys())
    
    # 매트릭스 생성
    matrix = []
    for stencil in stencils:
        row = [gadgets_by_stencil[stencil].get(cat, 0) for cat in all_categories]
        matrix.append(row)
    
    matrix = np.array(matrix)
    
    # 히트맵 그리기
    plt.figure(figsize=(12, max(6, len(stencils) * 0.3)))
    sns.heatmap(matrix, 
                xticklabels=all_categories, 
                yticklabels=stencils,
                annot=True, 
                fmt='d', 
                cmap='YlOrRd',
                cbar_kws={'label': 'Gadget Count'})
    
    plt.title(title, fontsize=14, fontweight='bold')
    plt.xlabel('Gadget Category', fontsize=12)
    plt.ylabel('Stencil ID', fontsize=12)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Heatmap saved: {output_file}")


def generate_summary(catalog, output_file):
    """텍스트 요약 생성"""
    with open(output_file, 'w') as f:
        f.write("="*60 + "\n")
        f.write("EXPERIMENT 1: STENCIL GADGET CATALOG SUMMARY\n")
        f.write("="*60 + "\n\n")
        
        f.write("Pre-Patch Statistics:\n")
        f.write(f"  Total Stencils: {catalog['pre_patch']['total_stencils']}\n")
        f.write(f"  Total Gadgets: {catalog['pre_patch']['total_gadgets']}\n\n")
        
        f.write("Post-Patch Statistics:\n")
        f.write(f"  Total Stencils: {catalog['post_patch']['total_stencils']}\n")
        f.write(f"  Total Gadgets: {catalog['post_patch']['total_gadgets']}\n\n")
        
        f.write("New Gadgets Introduced:\n")
        f.write(f"  Count: {catalog['new_gadgets']['count']}\n")
        f.write(f"  Percentage Increase: {catalog['new_gadgets']['count'] / max(catalog['pre_patch']['total_gadgets'], 1) * 100:.1f}%\n\n")
        
        f.write("Top 5 Stencils (by gadget count):\n")
        post_stencils = catalog['post_patch']['by_stencil']
        sorted_stencils = sorted(post_stencils.items(), 
                                key=lambda x: sum(x[1].values()), 
                                reverse=True)
        
        for i, (stencil, cats) in enumerate(sorted_stencils[:5], 1):
            total = sum(cats.values())
            f.write(f"  {i}. {stencil}: {total} gadgets\n")
            for cat, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"     - {cat}: {count}\n")
    
    print(f"✓ Summary saved: {output_file}")


def main():
    print("="*60)
    print("EXPERIMENT 1: STENCIL GADGET CATALOGING (Fast Mode)")
    print("Using pre-generated JIT code from Scenario A")
    print("="*60)
    
    # 출력 디렉토리
    output_dir = Path("gadget_analysis/experiment_1_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 저장된 데이터 로드
    print("\n[1/6] Loading pre-generated JIT data...")
    loader = JITDataLoader()
    
    try:
        scenario_data = loader.load_scenario('scenario_a')
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease generate JIT code first:")
        print("  python3 gadget_analysis/jit_code_generator.py --scenario a")
        return 1
    
    # 2. 분류기 초기화
    print("[2/6] Initializing gadget classifier...")
    classifier = GadgetClassifier()
    
    # 3. 패치 전 메모리 분석
    print("[3/6] Analyzing pre-patch memory...")
    pre_patch_memory = scenario_data.get('pre_patch', {})
    pre_gadgets, pre_all = analyze_memory_data(pre_patch_memory, classifier)
    
    # 4. 패치 후 메모리 분석
    print("[4/6] Analyzing post-patch memory...")
    post_patch_memory = scenario_data.get('post_patch', {})
    post_gadgets, post_all = analyze_memory_data(post_patch_memory, classifier)
    
    # 5. 카탈로그 생성
    print("[5/6] Creating catalog...")
    catalog = create_catalog(
        pre_gadgets, 
        post_gadgets, 
        output_dir / "gadget_catalog.json"
    )
    
    # 6. 시각화
    print("[6/6] Generating visualizations...")
    create_heatmap(
        pre_gadgets,
        output_dir / "heatmap_pre_patch.png",
        title="Gadget Distribution (Pre-Patch)"
    )
    
    create_heatmap(
        post_gadgets,
        output_dir / "heatmap_post_patch.png",
        title="Gadget Distribution (Post-Patch)"
    )
    
    generate_summary(catalog, output_dir / "summary.txt")
    
    # 완료
    print("\n" + "="*60)
    print("✓ EXPERIMENT 1 COMPLETED")
    print(f"✓ Results saved to: {output_dir}")
    print("="*60)
    
    print(f"\nQuick Stats:")
    print(f"  Pre-patch gadgets: {catalog['pre_patch']['total_gadgets']}")
    print(f"  Post-patch gadgets: {catalog['post_patch']['total_gadgets']}")
    print(f"  New gadgets: {catalog['new_gadgets']['count']}")


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
