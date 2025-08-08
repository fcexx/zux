.global lgdt_load
.global ltr_load
.global enter_user_mode_asm

lgdt_load:
    lgdt (%rdi)
    ret

ltr_load:
    mov %di, %ax
    ltr %ax
    ret

// void enter_user_mode_asm(uint64_t entry, uint64_t user_stack, uint16_t user_ds, uint16_t user_cs)
enter_user_mode_asm:
    // rdi=entry, rsi=user_stack, rdx=user_ds, rcx=user_cs
    // force RPL=3 on selectors
    or $3, %rdx
    or $3, %rcx
    // load user data segment selectors
    mov %dx, %ds
    mov %dx, %es
    mov %dx, %fs
    mov %dx, %gs

    // prepare iretq frame: SS, RSP, RFLAGS, CS, RIP
    pushq %rdx              // SS (user_ds | 3)
    pushq %rsi              // RSP
    pushfq
    pop %rax
    or $0x200, %rax         // ensure IF set
    pushq %rax              // RFLAGS
    pushq %rcx              // CS (user_cs | 3)
    pushq %rdi              // RIP (entry)
    iretq 