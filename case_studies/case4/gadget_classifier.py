#!/usr/bin/env python3
"""
Gadget Classification Framework
================================

가젯 생성 메커니즘을 6가지 카테고리로 분류:

1. Stencil-Aligned Gadgets: JIT stencil의 정상 명령어 경계에서 발견
2. Instruction-Unaligned Gadgets: 명령어 중간 바이트에서 디코딩 시작
3. Patch-Induced Gadgets: Patch 함수(patch_64, patch_32 등) 처리 중 생성
4. Address-Diversity Gadgets: 넓은 주소 공간 사용으로 patch 값 다양화
5. Patch-Unaligned Gadgets: Patch 영역 내 un-aligned 오프셋에서 발견
6. Syscall (Special): ret 불필요, 독립적으로 처리

각 분류는 발견 위치, 생성 메커니즘, 신뢰도를 포함합니다.
"""

import ctypes
import struct
from collections import defaultdict
from enum import Enum
from capstone import *

class GadgetCategory(Enum):
    """가젯 생성 메커니즘 카테고리"""
    STENCIL_ALIGNED = "stencil_aligned"           # 1. JIT stencil 정상 명령어
    INSTRUCTION_UNALIGNED = "instruction_unaligned" # 2. 명령어 중간 디코딩
    PATCH_INDUCED = "patch_induced"               # 3. Patch 함수 처리 중
    ADDRESS_DIVERSITY = "address_diversity"       # 4. 주소 공간 다양화
    PATCH_UNALIGNED = "patch_unaligned"           # 5. Patch 영역 un-aligned
    SYSCALL_SPECIAL = "syscall_special"           # 6. syscall 특수 처리

class GadgetClassifier:
    """가젯을 생성 메커니즘별로 분류"""
    
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.classified_gadgets = defaultdict(lambda: defaultdict(list))
        self.classification_results = {}  # 분류 통계 저장
        
        # Patch 함수 시그니처 (바이트 패턴)
        self.patch_signatures = {
            'patch_64': b'\x48\x8b',      # movabs 계열 (8바이트 주소)
            'patch_32': b'\x89',          # mov r/m32 계열
            'patch_x86_64_32rx': b'\x8d', # lea 계열
        }
        
        # 명령어 정렬 경계 (x86-64)
        self.instruction_boundaries = set()
        
    def classify_all_gadgets(self, base_addr, buffer, gadgets_dict):
        """
        모든 발견된 가젯을 분류
        
        Parameters:
        - base_addr: JIT 코드 시작 주소
        - buffer: JIT 코드 메모리 (bytes)
        - gadgets_dict: 발견된 가젯 딕셔너리 {gadget_name: [gadget_info]}
        
        Returns:
        - classified: {category: {gadget_name: [classified_info]}}
        """
        # 1단계: 명령어 경계 식별
        self._identify_instruction_boundaries(base_addr, buffer)
        
        # 2단계: 각 가젯 분류
        for gadget_name, gadget_list in gadgets_dict.items():
            for gadget_info in gadget_list:
                addr = gadget_info['address']
                offset = gadget_info['offset']
                
                # 특수 케이스: syscall
                if gadget_name == 'syscall':
                    category = GadgetCategory.SYSCALL_SPECIAL
                    self._add_classified_gadget(category, gadget_name, gadget_info, {
                        'reason': 'syscall requires no ret, special ROP handling',
                        'reliability': 'high'
                    })
                    continue
                
                # 일반 가젯 분류
                categories = self._classify_single_gadget(
                    addr, offset, buffer, gadget_name, gadget_info
                )
                
                # 가젯이 여러 카테고리에 속할 수 있음
                for category, metadata in categories:
                    self._add_classified_gadget(category, gadget_name, gadget_info, metadata)
        
        return self.classified_gadgets
    
    def _identify_instruction_boundaries(self, base_addr, buffer):
        """명령어 경계 식별 (정렬된 디스어셈블리)"""
        self.instruction_boundaries.clear()
        
        try:
            offset = 0
            while offset < len(buffer):
                insns = list(self.md.disasm(buffer[offset:offset+16], base_addr + offset))
                if insns:
                    self.instruction_boundaries.add(base_addr + offset)
                    # 다음 명령어 시작점으로 이동
                    offset += insns[0].size
                else:
                    # 디스어셈블 실패 시 1바이트씩 진행
                    offset += 1
        except:
            pass
    
    def _classify_single_gadget(self, addr, offset, buffer, gadget_name, gadget_info):
        """단일 가젯 분류 (여러 카테고리 가능)"""
        categories = []
        
        # 1. Stencil-Aligned vs Instruction-Unaligned
        if addr in self.instruction_boundaries:
            categories.append((
                GadgetCategory.STENCIL_ALIGNED,
                {
                    'reason': 'Found at instruction boundary',
                    'reliability': 'high',
                    'offset_alignment': 'aligned'
                }
            ))
        else:
            categories.append((
                GadgetCategory.INSTRUCTION_UNALIGNED,
                {
                    'reason': 'Found mid-instruction (unintended decoding)',
                    'reliability': 'medium',
                    'offset_alignment': 'unaligned'
                }
            ))
        
        # 2. Patch-Induced 체크
        patch_context = self._analyze_patch_context(offset, buffer)
        if patch_context:
            categories.append((
                GadgetCategory.PATCH_INDUCED,
                {
                    'reason': f"Found near {patch_context['type']} operation",
                    'reliability': 'medium',
                    'patch_type': patch_context['type'],
                    'patch_offset': patch_context['offset']
                }
            ))
            
            # 3. Patch-Unaligned 세부 분류
            if not self._is_aligned_to_patch_field(offset, patch_context):
                categories.append((
                    GadgetCategory.PATCH_UNALIGNED,
                    {
                        'reason': 'Gadget spans across patch field boundary',
                        'reliability': 'low',
                        'patch_field_offset': patch_context['field_offset']
                    }
                ))
        
        # 4. Address-Diversity 체크 (patch_64 값 다양성)
        if self._is_address_diversity_candidate(offset, buffer):
            categories.append((
                GadgetCategory.ADDRESS_DIVERSITY,
                {
                    'reason': 'Gadget bytes contain high-diversity address values',
                    'reliability': 'variable',
                    'address_bytes': self._extract_address_bytes(offset, buffer)
                }
            ))
        
        return categories
    
    def _analyze_patch_context(self, offset, buffer):
        """Patch 함수 컨텍스트 분석"""
        # ±16바이트 범위에서 patch 시그니처 검색
        search_start = max(0, offset - 16)
        search_end = min(len(buffer), offset + 16)
        context = buffer[search_start:search_end]
        
        for patch_type, signature in self.patch_signatures.items():
            pos = context.find(signature)
            if pos != -1:
                return {
                    'type': patch_type,
                    'offset': search_start + pos,
                    'field_offset': self._estimate_patch_field_offset(
                        offset, search_start + pos, patch_type
                    )
                }
        
        return None
    
    def _estimate_patch_field_offset(self, gadget_offset, patch_offset, patch_type):
        """Patch 필드 내 가젯 오프셋 추정"""
        if patch_type == 'patch_64':
            # movabs 명령: opcode(2) + reg(1) + imm64(8)
            field_start = patch_offset + 2
            field_end = field_start + 8
        elif patch_type == 'patch_32':
            # mov r/m32: opcode(1-2) + modrm(1) + imm32(4)
            field_start = patch_offset + 2
            field_end = field_start + 4
        elif patch_type == 'patch_x86_64_32rx':
            # lea: opcode(1-2) + modrm(1) + disp32(4)
            field_start = patch_offset + 2
            field_end = field_start + 4
        else:
            return None
        
        if field_start <= gadget_offset < field_end:
            return gadget_offset - field_start
        
        return None
    
    def _is_aligned_to_patch_field(self, offset, patch_context):
        """Patch 필드 경계에 정렬되었는지 확인"""
        field_offset = patch_context.get('field_offset')
        return field_offset is None  # None이면 필드 밖 = 정렬됨
    
    def _is_address_diversity_candidate(self, offset, buffer):
        """주소 다양성에 의한 가젯 후보인지 판단"""
        # 8바이트 정렬 위치에서 포인터 같은 값 체크
        if offset % 8 == 0 and offset + 8 <= len(buffer):
            ptr_value = struct.unpack('<Q', buffer[offset:offset+8])[0]
            
            # libc 주소 범위 (0x7f로 시작)
            if 0x7f0000000000 <= ptr_value < 0x800000000000:
                return True
        
        return False
    
    def _extract_address_bytes(self, offset, buffer):
        """주소 바이트 추출 (분석용)"""
        if offset + 8 <= len(buffer):
            return buffer[offset:offset+8].hex()
        return None
    
    def _add_classified_gadget(self, category, gadget_name, gadget_info, metadata):
        """분류된 가젯 추가"""
        classified_info = {
            **gadget_info,
            'category': category.value,
            'metadata': metadata
        }
        self.classified_gadgets[category][gadget_name].append(classified_info)
    
    def print_classification_report(self):
        """분류 결과 리포트 출력"""
        print("\n" + "="*70)
        print("GADGET CLASSIFICATION REPORT")
        print("="*70)
        
        category_descriptions = {
            GadgetCategory.STENCIL_ALIGNED: "1. JIT Stencil 정상 명령어 경계",
            GadgetCategory.INSTRUCTION_UNALIGNED: "2. 명령어 중간 디코딩 (Unintended)",
            GadgetCategory.PATCH_INDUCED: "3. Patch 함수 처리 중 생성",
            GadgetCategory.ADDRESS_DIVERSITY: "4. 주소 공간 다양화로 생성",
            GadgetCategory.PATCH_UNALIGNED: "5. Patch 영역 내 Un-aligned",
            GadgetCategory.SYSCALL_SPECIAL: "6. Syscall (ret 불필요)",
        }
        
        total_by_category = {}
        
        for category in GadgetCategory:
            desc = category_descriptions[category]
            gadgets = self.classified_gadgets[category]
            total = sum(len(v) for v in gadgets.values())
            total_by_category[category] = total
            
            print(f"\n{desc}")
            print(f"  Total: {total} gadgets")
            
            if gadgets:
                for gadget_name, gadget_list in sorted(gadgets.items()):
                    print(f"    {gadget_name:<12}: {len(gadget_list):>4} gadgets")
        
        # 요약 통계
        print("\n" + "-"*70)
        print("SUMMARY")
        print("-"*70)
        
        grand_total = sum(total_by_category.values())
        print(f"  Total classified gadgets: {grand_total}")
        print("\n  Distribution:")
        
        for category, count in sorted(total_by_category.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / grand_total * 100) if grand_total > 0 else 0
                print(f"    {category.value:<25}: {count:>5} ({percentage:>5.1f}%)")
    
    def export_classification(self):
        """분류 결과를 딕셔너리로 반환 (JSON 저장용)"""
        data = {}
        for category, gadgets in self.classified_gadgets.items():
            data[category.value] = {
                name: [
                    {
                        'address': f"0x{g['address']:016x}",
                        'offset': g['offset'],
                        'bytes': g['bytes'],
                        'instruction': g['instruction'],
                        'metadata': g['metadata']
                    }
                    for g in gadget_list
                ]
                for name, gadget_list in gadgets.items()
            }
        
        # 통계 추가
        total_by_category = {
            category.value: sum(len(v) for v in gadgets.values())
            for category, gadgets in self.classified_gadgets.items()
        }
        
        data['_summary'] = {
            'total_gadgets': sum(total_by_category.values()),
            'by_category': total_by_category
        }
        
        return data

def analyze_gadget_mechanisms(scanner):
    """
    RuntimeJITScanner 결과를 분석하여 가젯 생성 메커니즘 분류
    
    Parameters:
    - scanner: RuntimeJITScanner 인스턴스 (scan_functions 실행 완료 후)
    
    Returns:
    - classifier: GadgetClassifier 인스턴스
    """
    classifier = GadgetClassifier()
    
    # 스캔된 모든 함수의 JIT 메모리를 다시 읽어서 분류
    # (실제로는 scanner에서 이미 읽은 데이터를 재사용해야 하지만,
    #  여기서는 간단히 gadgets만 분류)
    
    # 임시: gadgets만으로 부분 분류 (완전한 분류는 JIT 메모리 필요)
    print("\n[*] Classifying gadgets by generation mechanism...")
    print("[!] Note: Full classification requires JIT memory re-scan")
    print("[!] Current: Partial classification based on gadget properties")
    
    return classifier

if __name__ == "__main__":
    print(__doc__)
    print("\nUsage:")
    print("  from gadget_classifier import GadgetClassifier")
    print("  classifier = GadgetClassifier()")
    print("  classified = classifier.classify_all_gadgets(base_addr, buffer, gadgets)")
    print("  classifier.print_classification_report()")
