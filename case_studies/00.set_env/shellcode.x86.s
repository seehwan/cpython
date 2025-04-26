; shellcode.s
; write(1, "OK\n", 3)
; exit(0)

BITS 64
global _start

section .text
_start:
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; file descriptor stdout
    lea rsi, [rel message]
    mov rdx, 3          ; length of message
    syscall

    mov rax, 60         ; syscall number for exit
    xor rdi, rdi        ; exit code 0
    syscall

section .data
message:
    db "OK", 10         ; "OK\n"

