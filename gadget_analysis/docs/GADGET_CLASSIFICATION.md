# Gadget Classification Framework

## Overview

이 프레임워크는 CPython JIT에서 발견된 ROP 가젯을 **생성 메커니즘**에 따라 6가지 카테고리로 분류합니다. 이를 통해 가젯의 신뢰도, 재현성, 그리고 공격 활용 가능성을 평가할 수 있습니다.

## Classification Categories

### 1. Stencil-Aligned Gadgets (정상 명령어 경계)
**정의**: JIT stencil의 정상적인 명령어 경계에서 발견된 가젯

**특징**:
- 의도된 명령어 디스어셈블리 결과
- 높은 재현성 (JIT 컴파일러 버전이 동일하면 항상 생성)
- 명령어 시작 오프셋과 가젯 시작 오프셋 일치

**신뢰도**: **HIGH**

**예시**:
```
0x00007f1fea9e7020: ret 
0x00007f1fea9e701f: pop rdi; ret
```

**비율**: 26-27% (10개 함수 기준)

**활용**:
- ROP 체인의 주요 빌딩 블록
- 예측 가능하고 안정적인 가젯 소스
- 스택 피벗, 레지스터 제어 등 핵심 기능

---

### 2. Instruction-Unaligned Gadgets (Unintended)
**정의**: 명령어 중간 바이트에서 디코딩을 시작하여 생성된 가젯

**특징**:
- **가장 많은 비율 차지 (55-56%)**
- x86-64 가변 길이 명령어 특성 활용
- 의도되지 않은 명령어 해석으로 생성
- 바이트 오프셋이 명령어 경계와 불일치

**신뢰도**: **MEDIUM**

**예시**:
```
정상 명령어: 48 8b 45 f8        mov rax, [rbp-8]
Unintended:        45 f8          rex.RB; clc (불완전)
Unintended:           f8 c3       clc; ret (가젯!)
```

**비율**: 55-56% (가장 많음)

**활용**:
- 가젯 다양성 증가
- 일부 희귀 패턴 확보 가능
- 버전/컴파일 옵션에 따라 변동 가능

**주의사항**:
- JIT 코드 변경 시 소멸 가능
- 패치나 최적화로 인한 바이트 변경에 취약

---

### 3. Patch-Induced Gadgets (Patch 함수 처리 중 생성)
**정의**: `patch_64`, `patch_32`, `patch_x86_64_32rx` 등 패치 함수가 즉시값을 쓸 때 생성되는 가젯

**특징**:
- Patch 시그니처 근처 (±16 바이트)에서 발견
- `patch_64`: `movabs` (0x48 0x8b) 계열 - 8바이트 주소
- `patch_32`: `mov r/m32` (0x89) 계열 - 4바이트 값
- `patch_x86_64_32rx`: `lea` (0x8d) 계열

**신뢰도**: **MEDIUM**

**예시**:
```
Patch 영역:
  48 b8 XX XX XX XX XX XX XX XX    movabs rax, <8-byte-addr>
           ^--- 패치 필드

만약 <8-byte-addr> = 0x5fc3c3c3c3c3c3c3 이면:
  오프셋 +6: c3 c3 c3 c3 c3 → 여러 개의 ret 가젯
```

**비율**: 17% (10개 함수 기준)

**활용**:
- 주소 다양성을 통해 특정 바이트 패턴 유도 가능
- 의도적인 상수 선택으로 가젯 생성 유도

---

### 4. Address-Diversity Gadgets (주소 공간 다양화)
**정의**: 넓은 주소 공간 사용으로 patch 필드 값이 다양해져 생성된 가젯

**특징**:
- 8바이트 포인터가 libc 범위 (0x7f00000000-0x800000000000)
- Spread allocation 전략으로 증가 가능
- 주소 바이트 자체가 유용한 명령어 형성

**신뢰도**: **LOW-VARIABLE**

**예시**:
```
주소: 0x00007f1fea5e7020
      ^^----- 상위 바이트가 0x5f, 0x7f 등 → pop rdi (5f), ...
```

**비율**: 0.1% (10개 함수 기준, 11개)

**활용**:
- 희귀 가젯 확보 가능
- 대규모 함수 생성 시 다양성 증가
- ASLR 우회 시 특정 주소 범위 타겟팅

**한계**:
- 예측 불가능
- 주소 공간 배치에 의존
- 소량으로만 발견됨

---

### 5. Patch-Unaligned Gadgets (Patch 영역 내 Un-aligned)
**정의**: Patch 영역 내부이지만 필드 경계와 정렬되지 않은 오프셋에서 발견된 가젯

**특징**:
- Patch 필드를 가로지르는 가젯
- 8바이트/4바이트 필드 중간에 걸침
- 매우 희귀

**신뢰도**: **LOW**

**예시**:
```
Patch 영역: [48 b8] [XX XX XX XX XX XX XX XX]
                      ^---^--- 필드 중간 오프셋에서 가젯
```

**비율**: 0.2% (10개 함수 기준, 21개)

**활용**:
- 거의 사용되지 않음
- 극히 특수한 경우에만 고려

---

### 6. Syscall (Special Case)
**정의**: `syscall` (0x0f 0x05) 명령어 - ret 없이도 execve 가능

**특징**:
- **매우 희귀** (실험에서 10개 함수당 1개)
- ROP 체인 종료용
- `ret` 불필요 - syscall 자체로 실행 전환

**신뢰도**: **HIGH (발견 시)**

**예시**:
```
0x00007f1fea9e8975: syscall 
```

**비율**: 0.0% (1개/7000+ 가젯)

**활용**:
- ROP 체인의 최종 단계
- `mov eax, 59; syscall` 형태 이상적
- execve("/bin/sh", NULL, NULL) 트리거

**발견 전략**:
- 대량 함수 생성 (200-500개 권장)
- 특정 연산 패턴 유도 (COMPARE_OP, BINARY_OP)

---

## Classification Algorithm

### 단계 1: 명령어 경계 식별
```python
# Capstone을 사용한 순차 디스어셈블리
def _identify_instruction_boundaries(base_addr, buffer):
    boundaries = set()
    offset = 0
    while offset < len(buffer):
        insns = capstone.disasm(buffer[offset:offset+16])
        if insns:
            boundaries.add(base_addr + offset)
            offset += insns[0].size
        else:
            offset += 1
    return boundaries
```

### 단계 2: 가젯 분류 (Multi-Category)
하나의 가젯이 **여러 카테고리에 동시에 속할 수 있음**:

```python
categories = []

# 1. Aligned vs Unaligned
if addr in instruction_boundaries:
    categories.append(STENCIL_ALIGNED)
else:
    categories.append(INSTRUCTION_UNALIGNED)

# 2. Patch context check (±16 bytes)
if patch_signature_nearby:
    categories.append(PATCH_INDUCED)
    
    # 3. Patch field alignment
    if not aligned_to_patch_field:
        categories.append(PATCH_UNALIGNED)

# 4. Address diversity (8-byte pointer in libc range)
if is_libc_address_pointer:
    categories.append(ADDRESS_DIVERSITY)

# 5. Syscall special case
if gadget_name == 'syscall':
    categories.append(SYSCALL_SPECIAL)
```

### 단계 3: 신뢰도 평가
```python
reliability_rules = {
    STENCIL_ALIGNED: "high",      # 항상 재현
    INSTRUCTION_UNALIGNED: "medium",  # 버전 의존
    PATCH_INDUCED: "medium",       # 주소 다양성 의존
    ADDRESS_DIVERSITY: "variable", # 예측 불가
    PATCH_UNALIGNED: "low",        # 매우 불안정
    SYSCALL_SPECIAL: "high"        # 발견 시 확실
}
```

---

## Experimental Results (10 Functions)

### Normal Allocation
```
Total gadgets: 7,252
JIT code size: 188,416 bytes
Warm-up time: 1079s (5000 iterations)

Classification:
  Instruction-Unaligned:  4,889 (55.6%)
  Stencil-Aligned:        2,362 (26.9%)
  Patch-Induced:          1,503 (17.1%)
  Patch-Unaligned:           21 ( 0.2%)
  Address-Diversity:         11 ( 0.1%)
  Syscall-Special:            1 ( 0.0%)
```

### Spread Allocation
```
Total gadgets: 7,403
JIT code size: 188,416 bytes
Warm-up time: 1080s (5000 iterations)

Classification:
  Instruction-Unaligned:  5,040 (56.4%)
  Stencil-Aligned:        2,362 (26.4%)
  Patch-Induced:          1,508 (16.9%)
  Patch-Unaligned:           21 ( 0.2%)
  Address-Diversity:         11 ( 0.1%)
  Syscall-Special:            1 ( 0.0%)
```

### Key Findings

1. **Unintended Gadgets Dominate**
   - 55-56%가 명령어 중간 디코딩으로 생성
   - Stencil-aligned 가젯은 27%뿐

2. **Spread Allocation 효과 미미 (10개 함수 스케일)**
   - Normal: 7,252 gadgets
   - Spread: 7,403 gadgets
   - 개선: **1.02x** (2% 증가)
   - 200-500 함수 스케일에서 더 큰 효과 예상

3. **Syscall 발견**
   - 10개 함수에서 각 1개씩 발견
   - 주소: Normal=0x7f1fea9e8975, Spread=0x7f1fea5e8975
   - 대규모 테스트로 더 많은 syscall 수집 가능

4. **Patch-Induced Gadgets 17%**
   - 의도적 상수 선택으로 증가 가능
   - MAGIC_VALUES 최적화 여지

5. **Address-Diversity 희귀 (0.1%)**
   - 10개 함수에서 11개만 발견
   - Spread 전략으로도 큰 차이 없음
   - 더 많은 함수 필요

---

## Usage

### 1. 분류 실행
```bash
cd /home/mobileos2/cpython/case_studies/case4
python3 test_runtime_jit_scan.py -n 50 -t both
```

### 2. 출력 예시
```
======================================================================
GADGET CLASSIFICATION REPORT
======================================================================

1. JIT Stencil 정상 명령어 경계
  Total: 2362 gadgets
    pop_rax     :  112 gadgets
    pop_rbx     :   27 gadgets
    pop_rcx     :  287 gadgets
    pop_rdi     : 1817 gadgets
    ...

2. 명령어 중간 디코딩 (Unintended)
  Total: 4889 gadgets
    ...

----------------------------------------------------------------------
SUMMARY
----------------------------------------------------------------------
  Total classified gadgets: 8787

  Distribution:
    instruction_unaligned    :  4889 ( 55.6%)
    stencil_aligned          :  2362 ( 26.9%)
    patch_induced            :  1503 ( 17.1%)
    ...
```

### 3. JSON Export
```json
{
  "stats": { ... },
  "gadgets": { ... },
  "classification": {
    "stencil_aligned": {
      "pop_rdi": [
        {
          "address": "0x00007f1fea9e701f",
          "offset": 31,
          "bytes": "5fc3",
          "instruction": "pop rdi; ret",
          "metadata": {
            "reason": "Found at instruction boundary",
            "reliability": "high",
            "offset_alignment": "aligned"
          }
        }
      ]
    },
    "_summary": {
      "total_gadgets": 8787,
      "by_category": { ... }
    }
  }
}
```

---

## Implementation

### Core Classes

#### `GadgetCategory` (Enum)
```python
class GadgetCategory(Enum):
    STENCIL_ALIGNED = "stencil_aligned"
    INSTRUCTION_UNALIGNED = "instruction_unaligned"
    PATCH_INDUCED = "patch_induced"
    ADDRESS_DIVERSITY = "address_diversity"
    PATCH_UNALIGNED = "patch_unaligned"
    SYSCALL_SPECIAL = "syscall_special"
```

#### `GadgetClassifier`
```python
class GadgetClassifier:
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.classified_gadgets = defaultdict(lambda: defaultdict(list))
        self.patch_signatures = {
            'patch_64': b'\x48\x8b',
            'patch_32': b'\x89',
            'patch_x86_64_32rx': b'\x8d'
        }
    
    def classify_all_gadgets(self, base_addr, buffer, gadgets_dict):
        # 1. 명령어 경계 식별
        self._identify_instruction_boundaries(base_addr, buffer)
        
        # 2. 각 가젯 분류
        for gadget_name, gadget_list in gadgets_dict.items():
            for gadget_info in gadget_list:
                categories = self._classify_single_gadget(...)
                for category, metadata in categories:
                    self._add_classified_gadget(...)
```

### Integration with RuntimeJITScanner

```python
class RuntimeJITScanner:
    def __init__(self):
        self.classifier = GadgetClassifier()
        self.jit_memory_cache = []  # [(base_addr, buffer)]
    
    def _scan_single_function(self, func, func_idx):
        # JIT 메모리 읽기
        buffer = ctypes.string_at(jit_addr, jit_size)
        
        # 캐시에 저장 (분류용)
        self.jit_memory_cache.append((jit_addr, buffer))
        
        # 가젯 스캔
        self._scan_buffer_for_gadgets(jit_addr, buffer)
    
    def _classify_gadgets(self):
        for base_addr, buffer in self.jit_memory_cache:
            self.classifier.classify_all_gadgets(
                base_addr, buffer, self.gadgets
            )
```

---

## Security Implications

### Attack Perspective

1. **Reliable Gadgets (High Priority)**
   - Stencil-aligned (27%)
   - Syscall (희귀하지만 critical)
   - 버전 간 호환성 높음

2. **Opportunistic Gadgets (Medium Priority)**
   - Instruction-unaligned (55%)
   - Patch-induced (17%)
   - 가젯 다양성 확보에 유용
   - 버전/환경 테스트 필요

3. **Unreliable Gadgets (Low Priority)**
   - Patch-unaligned (0.2%)
   - Address-diversity (0.1%)
   - 백업용으로만 사용

### Defense Perspective

1. **Mitigation Priority**
   - Stencil-aligned 가젯 감소: JIT stencil 재설계
   - Unintended 가젯 방지: 명령어 정렬 강제, NOP 삽입
   - Patch 영역 난독화: 랜덤 패딩 추가

2. **Detection Strategy**
   - 높은 가젯 밀도 탐지 (7000+/188KB = 37 gadgets/KB)
   - Syscall 패턴 모니터링
   - 비정상적 메모리 스캔 행위 탐지

---

## Future Work

1. **Large-Scale Validation (200-500 functions)**
   - Address diversity 효과 측정
   - Syscall 발견 빈도 분석
   - 분류 비율 변화 관찰

2. **Stencil Optimization**
   - 특정 stencil 타겟팅으로 가젯 생성
   - MAGIC_VALUES 최적화
   - 함수 템플릿 다양화

3. **Cross-Version Analysis**
   - CPython 3.13 vs 3.14
   - JIT 옵션별 차이 (--with-jit vs --without-jit)
   - 플랫폼별 차이 (x86-64, ARM64)

4. **Defense Mechanism Evaluation**
   - CFI (Control Flow Integrity) 효과
   - JIT Code Signing
   - Randomized Stencil Ordering

---

## References

- **gadget_classifier.py**: 분류 프레임워크 구현 (400+ lines)
- **test_runtime_jit_scan.py**: 통합 테스트 및 분석
- **TEST_RUNTIME_JIT_SCAN.md**: 실행 가이드
- **stencil_gadget_scanner.py**: 정적 stencil 분석

---

## Authors & Date

- Classification framework implemented: 2024-11-13
- 10-function experimental validation: 2024-11-13
- Documentation: 2024-11-13
