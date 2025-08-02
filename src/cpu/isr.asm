BITS 64
    DEFAULT REL

%macro PUSH_REGS 0
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro POP_REGS 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
%endmacro

extern isr_dispatch

section .text

%define ISR_ATTR 0x8E ; not used here but for documentation

; Список векторов с CPU error-code
%define ERR_VECTORS {8,10,11,12,13,14,17}

%macro ISR_NOERR 1
isr%1:
    PUSH_REGS
    xor rax, rax
    push rax            ; fake error code
    mov rax, %1
    push rax            ; interrupt number
    mov rax, [rsp + 8 * 18]  ; RIP from stack (after pushing registers)
    push rax            ; rip
    mov rax, rsp
    add rax, 8 * 20     ; RSP before interrupt
    push rax            ; rsp
    mov rdi, rsp        ; rdi -> cpu_registers_t
    call isr_dispatch
    add rsp, 32         ; pop rip, rsp, vector + error code
    POP_REGS
    iretq
%endmacro

%macro ISR_ERR 1
isr%1:
    pop rax             ; drop CPU-provided error code
    PUSH_REGS
    push rax            ; real error code
    mov rax, %1
    push rax            ; interrupt number
    mov rax, [rsp + 8 * 18]  ; RIP from stack (after pushing registers)
    push rax            ; rip
    mov rax, rsp
    add rax, 8 * 20     ; RSP before interrupt
    push rax            ; rsp
    mov rdi, rsp        ; rdi -> cpu_registers_t
    call isr_dispatch
    add rsp, 32         ; pop rip, rsp, vector + error code
    POP_REGS
    iretq
%endmacro

; Генерация 256 ISR
section .text
%assign i 0
%rep 256
    %if (i == 8) || (i == 10) || (i == 11) || (i == 12) || (i == 13) || (i == 14) || (i == 17)
        ISR_ERR i
    %else
        ISR_NOERR i
    %endif
%assign i i+1
%endrep

section .rodata
global isr_stub_table
isr_stub_table:
%assign i 0
%rep 256
    dq isr%+i
%assign i i+1
%endrep 