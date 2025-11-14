# JIT Code Generation & Experiment Architecture

이 디렉토리는 **효율적인 실험 실행**을 위해 JIT 코드 생성과 분석을 분리한 아키텍처를 제공합니다.

## 🏗️ 아키텍처 개요

### 문제점
- JIT 컴파일 워밍업에 시간이 오래 걸림 (100개 함수 = ~90분)
- 여러 실험이 동일한 JIT 코드를 재사용할 수 있음
- 매 실험마다 코드 생성을 반복하는 것은 비효율적

### 해결책
1. **한 번 생성** - JIT 코드를 시나리오별로 생성하고 메모리 덤프 저장
2. **여러 번 분석** - 저장된 데이터를 여러 실험에서 재사용
3. **시나리오 그룹화** - 유사한 요구사항을 가진 실험들을 그룹화

## 📊 시나리오 분류

### Scenario A: 표준 JIT 함수 (실험 1, 2, 3 공유)
- **생성**: 100개 함수, 다양한 opcode 조합, optimizer on/off
- **저장**: `jit_captures/scenario_a.pkl`
- **공유 실험**:
  1. **실험 1** - Stencil Gadget Cataloging
  2. **실험 2** - Unaligned Decoding (0-7 byte offsets)
  3. **실험 3** - Patch Function Impact

### Scenario B: 메모리 스케일링 (실험 4)
- **생성**: 1, 8, 32, 80개 영역 (각 128KB)
- **저장**: `jit_captures/scenario_b.pkl`
- **실험**: Executor Memory Scaling

### Scenario C: Ret-free Chains (실험 5)
- **생성**: syscall/pop/indirect branch 가젯 풀
- **저장**: `jit_captures/scenario_c.pkl`
- **실험**: Ret-Free Syscall Taxonomy

### Scenario D: Opcode-Sensitive (실험 6)
- **생성**: `spray_execve` 템플릿 사용
- **저장**: `jit_captures/scenario_d.pkl`
- **실험**: Opcode-Sensitive Function Generator

## 🚀 사용 방법

### Step 1: JIT 코드 생성 (한 번만 실행)

```bash
# 모든 시나리오 생성 (시간이 오래 걸림!)
python3 gadget_analysis/jit_code_generator.py --scenario all

# 또는 개별 시나리오 생성
python3 gadget_analysis/jit_code_generator.py --scenario a  # 실험 1,2,3용
python3 gadget_analysis/jit_code_generator.py --scenario b  # 실험 4용
python3 gadget_analysis/jit_code_generator.py --scenario c  # 실험 5용
python3 gadget_analysis/jit_code_generator.py --scenario d  # 실험 6용
```

**예상 시간**: Scenario A는 약 90분 소요 (100개 함수 × 6000 iterations)

### Step 2: 실험 실행 (빠름!)

```bash
# 실험 1: 스텐실 가젯 카탈로그 (Scenario A 사용)
python3 gadget_analysis/experiment_1_refactored.py

# 실험 2: 언얼라인드 디코딩 (Scenario A 재사용)
python3 gadget_analysis/experiment_2_unaligned.py

# 실험 3: 패치 함수 영향 (Scenario A 재사용)
python3 gadget_analysis/experiment_3_patch_impact.py
```

**예상 시간**: 각 실험 1-2분 (JIT 생성 없이 분석만)

### Step 3: 결과 확인

```bash
ls -la gadget_analysis/experiment_*_results/
```

각 실험 디렉토리에 다음 파일들이 생성됩니다:
- `*.json` - 원시 데이터
- `*.png` - 시각화 (히트맵, 차트, 그래프)
- `*.txt` - 요약 보고서

## 📁 파일 구조

```
gadget_analysis/
├── jit_code_generator.py       # JIT 코드 생성 및 메모리 캡처
├── jit_data_loader.py          # 저장된 데이터 로드 유틸리티
│
├── experiment_1_refactored.py  # 실험 1 (Scenario A 사용)
├── experiment_2_unaligned.py   # 실험 2 (Scenario A 재사용)
├── experiment_3_patch_impact.py # 실험 3 (Scenario A 재사용)
│
├── jit_captures/               # 생성된 JIT 메모리 덤프
│   ├── scenario_a.pkl
│   ├── scenario_a_meta.json
│   ├── scenario_b.pkl
│   ├── scenario_b_meta.json
│   ├── scenario_c.pkl
│   ├── scenario_c_meta.json
│   ├── scenario_d.pkl
│   └── scenario_d_meta.json
│
└── experiment_*_results/       # 실험 결과 출력
    ├── experiment_1_results/
    ├── experiment_2_results/
    └── experiment_3_results/
```

## 🔍 데이터 형식

### 캡처된 데이터 구조 (scenario_a.pkl)

```python
{
    'scenario': 'scenario_a',
    'function_count': 100,
    'pre_patch': {
        'regions': [
            {
                'address': 0x7f1234567000,
                'size': 131072,
                'stencil_id': 'BINARY_OP_ADD',
                'code': b'\x48\x89...',  # 원시 바이트
                'gadgets': [
                    {'address': 0x..., 'bytes': 'c3', 'type': 'ret'},
                    ...
                ]
            },
            ...
        ]
    },
    'post_patch': { ... },  # 동일 구조
    'functions': [...]  # 샘플 함수 정보
}
```

## ⚡ 성능 비교

### 기존 방식 (실험마다 JIT 생성)
```
실험 1: 90분 (생성 90분 + 분석 1분)
실험 2: 90분 (생성 90분 + 분석 1분)
실험 3: 90분 (생성 90분 + 분석 1분)
합계: 270분 (4.5시간)
```

### 새 방식 (한 번 생성, 여러 번 분석)
```
생성: 90분 (Scenario A 한 번만)
실험 1: 1분
실험 2: 1분
실험 3: 1분
합계: 93분 (1.5시간)
```

**시간 절약**: 177분 (약 3시간) → **66% 단축**

## 🛠️ 고급 사용법

### 캡처된 데이터 조회

```python
from gadget_analysis.jit_data_loader import JITDataLoader

loader = JITDataLoader()

# 사용 가능한 시나리오 확인
loader.print_summary()

# 특정 시나리오 로드
data = loader.load_scenario('scenario_a')

# 패치 전/후 메모리 추출
pre_patch = loader.get_pre_patch_memory('scenario_a')
post_patch = loader.get_post_patch_memory('scenario_a')
```

### 커스텀 분석 스크립트 작성

```python
from gadget_analysis.jit_data_loader import JITDataLoader
from gadget_analysis.classifier import GadgetClassifier

loader = JITDataLoader()
data = loader.load_scenario('scenario_a')

# 패치 후 가젯만 분석
post_memory = data['post_patch']
regions = post_memory.get('regions', [])

classifier = GadgetClassifier()
for region in regions:
    for gadget in region.get('gadgets', []):
        category = classifier.classify(gadget)
        print(f"Gadget: {gadget['bytes']} -> {category}")
```

## 📝 주의사항

1. **메모리 덤프 크기**: 각 scenario pkl 파일은 수백 MB가 될 수 있음
2. **재생성 필요 시**: CPython JIT 코드가 변경되면 재생성 필요
3. **실제 패치 로깅**: 현재는 pre/post 비교로 추정, 실제로는 emitter 계측 필요

## 🔗 관련 문서

- [gadget_analysis_plan.md](docs/gadget_analysis_plan.md) - 전체 실험 계획
- [HIGH_YIELD_OPCODES.md](docs/HIGH_YIELD_OPCODES.md) - High-yield opcode 분석
- [README.md](gadget_analysis/README.md) - 가젯 분석 프레임워크 개요

## 🤝 기여

새로운 시나리오나 실험 추가 시:
1. `jit_code_generator.py`에 캡처 메서드 추가
2. 새 `experiment_N_*.py` 파일 생성
3. 이 README 업데이트

## 📄 라이선스

This project follows the CPython license.
