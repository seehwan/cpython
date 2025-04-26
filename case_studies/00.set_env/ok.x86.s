BITS 64

global _start

section .text
_start:
    ; write(1, message, 3)
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; file descriptor (stdout)
    lea rsi, [rel message] ; address of "OK\n"
    mov rdx, 3          ; message length = 3
    syscall             ; do write(1, message, 3)

    ; exit(0)
    mov rax, 60         ; syscall number for exit
    xor rdi, rdi        ; exit code = 0
    syscall             ; do exit(0)

section .data
message:
    db 'OK', 10         ; "OK\n"

