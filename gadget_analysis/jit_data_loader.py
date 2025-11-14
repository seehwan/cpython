#!/usr/bin/env python3
"""
JIT Data Loader - 저장된 JIT 코드 메모리 덤프를 로드하여 실험에서 재사용
"""
import pickle
import json
from pathlib import Path
from typing import Dict, Any, Optional


class JITDataLoader:
    """저장된 JIT 메모리 덤프 로더"""
    
    def __init__(self, data_dir: str = "gadget_analysis/jit_captures"):
        self.data_dir = Path(data_dir)
        if not self.data_dir.exists():
            raise FileNotFoundError(f"JIT capture directory not found: {data_dir}")
    
    def load_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """
        특정 시나리오 데이터 로드
        
        Args:
            scenario_name: 'scenario_a', 'scenario_b', 'scenario_c', 'scenario_d'
        
        Returns:
            캡처된 메모리 데이터 딕셔너리
        """
        data_file = self.data_dir / f"{scenario_name}.pkl"
        
        if not data_file.exists():
            raise FileNotFoundError(
                f"Scenario data not found: {data_file}\n"
                f"Please run: python3 gadget_analysis/jit_code_generator.py --scenario {scenario_name[-1]}"
            )
        
        with open(data_file, 'rb') as f:
            data = pickle.load(f)
        
        print(f"✓ Loaded scenario data: {scenario_name}")
        return data
    
    def load_metadata(self, scenario_name: str) -> Dict[str, Any]:
        """시나리오 메타데이터 로드"""
        meta_file = self.data_dir / f"{scenario_name}_meta.json"
        
        if not meta_file.exists():
            return {}
        
        with open(meta_file, 'r') as f:
            meta = json.load(f)
        
        return meta
    
    def list_scenarios(self) -> list:
        """사용 가능한 시나리오 목록"""
        scenarios = []
        for pkl_file in self.data_dir.glob("scenario_*.pkl"):
            scenario_name = pkl_file.stem
            scenarios.append(scenario_name)
        return sorted(scenarios)
    
    def get_pre_patch_memory(self, scenario_name: str = 'scenario_a') -> Dict[str, Any]:
        """패치 전 메모리 데이터 추출"""
        data = self.load_scenario(scenario_name)
        return data.get('pre_patch', {})
    
    def get_post_patch_memory(self, scenario_name: str = 'scenario_a') -> Dict[str, Any]:
        """패치 후 메모리 데이터 추출"""
        data = self.load_scenario(scenario_name)
        return data.get('post_patch', {})
    
    def get_memory_regions(self, scenario_name: str = 'scenario_a', 
                          patch_state: str = 'post') -> list:
        """
        메모리 영역 리스트 추출
        
        Args:
            scenario_name: 시나리오 이름
            patch_state: 'pre' 또는 'post'
        """
        if patch_state == 'pre':
            memory = self.get_pre_patch_memory(scenario_name)
        else:
            memory = self.get_post_patch_memory(scenario_name)
        
        return memory.get('regions', [])
    
    def print_summary(self):
        """사용 가능한 시나리오 요약 출력"""
        print("\n" + "="*60)
        print("Available JIT Capture Scenarios")
        print("="*60)
        
        scenarios = self.list_scenarios()
        
        if not scenarios:
            print("\n⚠ No captured data found!")
            print(f"   Run: python3 gadget_analysis/jit_code_generator.py")
            return
        
        for scenario in scenarios:
            meta = self.load_metadata(scenario)
            print(f"\n[{scenario}]")
            for key, value in meta.items():
                print(f"  {key}: {value}")
        
        print("\n" + "="*60)


def main():
    """데이터 로더 테스트 및 요약"""
    loader = JITDataLoader()
    loader.print_summary()


if __name__ == '__main__':
    main()
