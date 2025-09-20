.intel_syntax noprefix
.global syscall_entry
.extern syscall_entry_c
.extern syscall_kernel_rsp0
.extern exec_new_rip
.extern exec_new_rsp
.extern exec_trampoline
.extern exec_child_rax
.extern syscall_saved_user_rsp
.extern syscall_saved_user_rcx

// On entry (64-bit):
//  RAX=nr, RDI,RSI,RDX,R10,R8,R9=args; RCX=user RIP; R11=user RFLAGS; RSP=user stack
// Exits via SYSRET to RCX/R11 with RAX=retval
syscall_entry:
    // Switch to kernel stack (single-core simplification)
    // Save user state
    mov qword ptr [rip + syscall_saved_user_rsp], rsp
    mov qword ptr [rip + syscall_saved_user_rcx], rcx
    // Switch to kernel stack (single-core simplification)
    mov rsp, qword ptr [rip + syscall_kernel_rsp0]
    and rsp, -16              // align to 16
    // Save callee-saved registers (preserve user RBX,RBP,R12..R15 across syscall)
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    // Build SyscallFrame on stack (top to bottom)
    push rax                  // nr
    push rdi                  // a1
    push rsi                  // a2
    push rdx                  // a3
    push r10                  // a4
    push r8                   // a5
    push r9                   // a6
    push qword ptr [rip + syscall_saved_user_rsp] // user_rsp
    push qword ptr [rip + syscall_saved_user_rcx] // user_rcx
    push r11                  // user_r11

    mov r13, rsp              // frame ptr in r13 (don't clobber rbx)
    // Align for call: make (rsp % 16)==8 before 'call'
    sub rsp, 8
    mov rdi, r13
    call syscall_entry_c
    add rsp, 8
    // Preserve syscall return value across trampoline check
    mov r12, rax
    // Check for exec/vfork trampoline flag
    mov rax, qword ptr [rip + exec_trampoline]
    test rax, rax
    je 1f
    // Compute RFLAGS value into r11 (ensure bit1=1, NT=0)
    mov r11, qword ptr [r13 + 0]
    or r11, 0x2
    and r11, ~0x4000
    // Skip syscall frame and restore callee-saved before returning
    lea rsp, [r13 + 80]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    // Build IRET frame and return to new user entry/stack
    push 0x23                       // SS
    mov rdi, qword ptr [rip + exec_new_rsp]
    push rdi                        // RSP
    push r11                        // RFLAGS
    push 0x1b                       // CS
    mov rsi, qword ptr [rip + exec_new_rip]
    push rsi                        // RIP
    // Set RAX for child/parent as requested by kernel
    mov rax, qword ptr [rip + exec_child_rax]
    // clear child rax after use
    mov qword ptr [rip + exec_child_rax], 0
    // clear trampoline flag
    mov qword ptr [rip + exec_trampoline], 0
    iretq
// ensure newline at end of file
1:
    // Restore user state and return via IRET
    // Restore return value to RAX
    mov rax, r12
    // Compute RFLAGS into r11 (ensure bit1=1, NT=0)
    mov r11, qword ptr [r13 + 0]
    or r11, 0x2
    and r11, ~0x4000
    // Restore volatile argument regs per Linux SYSCALL ABI (rcx,r11 are handled separately)
    mov rdi, qword ptr [r13 + 64]    // a1
    mov rsi, qword ptr [r13 + 56]    // a2
    mov rdx, qword ptr [r13 + 48]    // a3
    mov r10, qword ptr [r13 + 40]    // a4
    mov r8,  qword ptr [r13 + 32]    // a5
    mov r9,  qword ptr [r13 + 24]    // a6
    // Skip syscall frame and restore callee-saved regs before switching privilege
    lea rsp, [r13 + 80]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    // Build IRET frame last: SS,RSP,RFLAGS,CS,RIP (use saved globals)
    push 0x23
    push qword ptr [rip + syscall_saved_user_rsp]
    push r11
    push 0x1b
    push qword ptr [rip + syscall_saved_user_rcx]
    iretq