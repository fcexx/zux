BITS 64
GLOBAL _start

SECTION .data
path: db "/bin/sh",0
argv: dq path, 0
envp: dq 0
msg:  db "execve failed",10
msglen: equ $-msg

SECTION .text
_start:
    ; execve(path, argv, envp)
    mov rax, 59
    lea rdi, [rel path]
    lea rsi, [rel argv]
    lea rdx, [rel envp]
    syscall

    ; write(1, msg, msglen)
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg]
    mov rdx, msglen
    syscall

    ; exit(1)
    mov rax, 60
    mov rdi, 1
    syscall
