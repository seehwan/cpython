# Runtime JIT Memory Gadget Scanner Test

## 개요

이 테스트 스크립트는 `PATCH_GADGET_ANALYSIS.md`에서 분석한 **런타임 JIT 메모리 스캔** 기법을 실제로 검증합니다.

### 핵심 아이디어

1. **많은 JIT 함수 생성** (gadget spray)
2. **런타임에 패치된 메모리 직접 스캔**
3. **patch_64, patch_x86_64_32rx, patch_32r에서 우연히 생긴 gadget 발견**
4. **Unintended instruction 활용** (모든 바이트 오프셋 스캔)

### 테스트 시나리오

- **Normal allocation**: 연속된 메모리 영역에 JIT 함수 생성
- **Spread allocation**: 넓은 주소 영역에 분산 배치 (주소 다양성 극대화)
- **Comparison**: 두 방식의 gadget 생성 효율 비교

## 파일 구성

```
test_runtime_jit_scan.py    # 메인 테스트 스크립트
run_jit_scan_test.sh        # 간편 실행 스크립트
TEST_RUNTIME_JIT_SCAN.md    # 이 문서
```

## 의존성

```bash
# Python 패키지
pip install capstone

# 필수 모듈 (같은 디렉토리)
jitexecleak.py              # JIT 코드 주소 추출
```

## 빠른 시작

### 방법 1: 간편 스크립트 사용

```bash
./run_jit_scan_test.sh
```

대화형 메뉴에서 선택:
- Quick test (100 functions)
- Standard test (1000 functions)  
- Large test (5000 functions)
- Custom test

### 방법 2: 직접 실행

```bash
# 기본 테스트 (1000 함수, 양쪽 비교)
python3 test_runtime_jit_scan.py

# Normal allocation만 테스트
python3 test_runtime_jit_scan.py -n 1000 -t normal

# Spread allocation만 테스트
python3 test_runtime_jit_scan.py -n 1000 -t spread

# 5000 함수로 대규모 테스트
python3 test_runtime_jit_scan.py -n 5000 -t both
```

## 사용법

```
usage: test_runtime_jit_scan.py [-h] [-n NUM_FUNCTIONS] [-t {normal,spread,both}] [--no-comparison]

옵션:
  -n, --num-functions NUM_FUNCTIONS
                        생성할 JIT 함수 개수 (기본값: 1000)
  -t, --test {normal,spread,both}
                        테스트 시나리오 (기본값: both)
  --no-comparison       비교 생략 (테스트만 실행)
```

## 예상 결과

### Normal Allocation (1000 함수)

```
[Gadgets Found]
  pop_rax      :   ~800 gadgets
  pop_rdi      :   ~800 gadgets
  pop_rsi      :   ~750 gadgets
  pop_rdx      :   ~700 gadgets
  syscall      :   ~500 gadgets
  ret          :  ~5000 gadgets
  
Total: ~8,500 gadgets
```

### Spread Allocation (1000 함수)

```
[Gadgets Found]
  pop_rax      :  ~1600 gadgets  (2x)
  pop_rdi      :  ~1600 gadgets  (2x)
  pop_rsi      :  ~1500 gadgets  (2x)
  pop_rdx      :  ~1400 gadgets  (2x)
  syscall      :  ~1000 gadgets  (2x)
  ret          : ~10000 gadgets  (2x)
  
Total: ~17,000 gadgets (2x improvement)
```

### 주소 다양성 (Address Diversity)

**Normal Allocation (좁은 영역)**:
```
Byte 0: 200+ unique values (7.8 bits entropy)
Byte 1: 80+ unique values  (6.3 bits entropy)
Byte 2: 2-3 unique values  (1.0 bits entropy)  ← 거의 고정
Byte 3: 2-3 unique values  (1.0 bits entropy)  ← 거의 고정
Byte 4-7: 1 unique value   (0.0 bits entropy)  ← 완전 고정
```

**Spread Allocation (넓은 영역)**:
```
Byte 0: 250+ unique values (8.0 bits entropy)
Byte 1: 200+ unique values (7.6 bits entropy)
Byte 2: 20+ unique values  (4.3 bits entropy)  ← 개선!
Byte 3: 10+ unique values  (3.3 bits entropy)  ← 개선!
Byte 4: 2-3 unique values  (1.0 bits entropy)
Byte 5-7: 1 unique value   (0.0 bits entropy)
```

## 출력 파일

### runtime_scan_normal.json

Normal allocation 테스트 결과:
- 발견된 모든 gadget 주소
- 스캔 통계
- 주소 다양성 측정

### runtime_scan_spread.json

Spread allocation 테스트 결과:
- 발견된 모든 gadget 주소
- 스캔 통계
- 주소 다양성 측정

### 결과 분석

```bash
# JSON 포맷으로 보기
python3 -m json.tool runtime_scan_normal.json | less

# Gadget 개수 확인
jq '.stats.gadgets_found' runtime_scan_normal.json

# 특정 gadget 주소 확인
jq '.gadgets.pop_rax[] | .address' runtime_scan_normal.json | head -10
```

## 핵심 검증 사항

### 1. Runtime 스캔의 실용성
- ✅ ASLR 문제 해결: 이미 패치된 메모리 읽음
- ✅ 충분한 gadget: 1000 함수로 수천 개 발견
- ✅ 빠른 스캔: 1-2초 이내 완료

### 2. JIT 영역 넓이의 영향
- ✅ Spread allocation이 2-3배 더 많은 gadget 생성
- ✅ 주소 다양성 증가 확인 (Byte 2-3의 엔트로피 증가)
- ✅ patch_64 (8바이트) 주소의 상위 바이트 다양화

### 3. Unintended Instruction의 효과
- ✅ 정렬되지 않은 오프셋에서도 gadget 발견
- ✅ 8개 디코딩 위치 모두 활용

## 성능 벤치마크

### 예상 실행 시간

| 함수 개수 | 생성 시간 | Warm-up | 스캔 시간 | 총 시간 |
|----------|----------|---------|----------|---------|
| 100      | ~5초     | ~10초   | ~0.2초   | ~15초   |
| 1,000    | ~50초    | ~100초  | ~2초     | ~2.5분  |
| 5,000    | ~4분     | ~8분    | ~10초    | ~12분   |
| 10,000   | ~8분     | ~16분   | ~20초    | ~24분   |

### 메모리 사용량

- 함수당 평균 메모리: ~100KB
- 1,000 함수: ~100MB
- 10,000 함수: ~1GB

## 문제 해결

### JIT 컴파일 실패

```
[!] Function X warmup failed: ...
```

**원인**: JIT 컴파일이 활성화되지 않았거나 Tier 2가 비활성화됨

**해결**:
```bash
# JIT 활성화 확인
python3 -c "import sys; print(sys._is_gil_enabled())"

# Tier 2 활성화
export PYTHON_JIT=1
```

### 메모리 접근 실패

```
[!] JIT memory failed
```

**원인**: JIT 코드 주소를 얻을 수 없거나 메모리 읽기 권한 없음

**해결**:
- `jitexecleak.py`가 올바르게 구현되어 있는지 확인
- CPython 내부 API 접근 권한 확인

### Gadget이 거의 발견되지 않음

```
Total gadgets found: <100
```

**원인**: 
1. JIT 함수가 너무 간단하여 patch가 적음
2. Warm-up 횟수가 부족하여 JIT 컴파일 안 됨

**해결**:
- 함수 개수 증가 (`-n 5000`)
- Warm-up 반복 횟수 증가 (코드 수정)

## 실험 확장

### 다양한 함수 패턴 테스트

`test_runtime_jit_scan.py`의 `_create_jit_function()` 수정:

```python
def _create_jit_function(self, seed):
    # 다른 패턴 시도:
    # - 딕셔너리 연산 (STORE_SUBSCR_DICT)
    # - 클래스 속성 접근 (LOAD_ATTR)
    # - 함수 호출 (CALL)
    # - 예외 처리 (try/except)
    ...
```

### 더 많은 Gadget 패턴

`GADGET_PATTERNS` 딕셔너리에 추가:

```python
GADGET_PATTERNS = {
    # 기존...
    'xor_eax': b'\x31\xc0',       # xor eax, eax
    'xor_edx': b'\x31\xd2',       # xor edx, edx
    'add_rsp': b'\x48\x83\xc4',   # add rsp, N
    ...
}
```

## 참고 문서

- `PATCH_GADGET_ANALYSIS.md` - 전체 이론적 분석
- `README.md` - 프로젝트 개요
- `gadget_chain_parallel.py` - 실제 ROP chain 구성 예시

## 라이선스

이 코드는 CPython 프로젝트의 일부로, Python Software Foundation License를 따릅니다.
