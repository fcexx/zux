#include <syscall.h>
#include <thread.h>
#include <vbetty.h>
#include <debug.h>

static void sys_yield() { thread_yield(); }

static long sys_write(int fd, const char* buf, unsigned long len) {
    // For now, only stdout
    if (fd != 1 || !buf || len == 0) return -1;
    for (unsigned long i = 0; i < len; ++i) {
        if (buf[i] == '\n') vbetty_put_char('\n');
        else vbetty_put_char(buf[i]);
    }
    return (long)len;
}

static void sys_exit(int code) {
    (void)code;
    thread_stop(thread_current()->tid);
    thread_yield();
}

extern "C" void syscall_dispatch(cpu_registers_t* regs) {
    uint64_t nr = regs->rax;
    switch (nr) {
        case SYS_YIELD:
            sys_yield();
            break;
        case SYS_WRITE:
            regs->rax = sys_write((int)regs->rdi, (const char*)regs->rsi, regs->rdx);
            break;
        case SYS_EXIT:
            sys_exit((int)regs->rdi);
            break;
        default:
            PrintfQEMU("syscall: unknown nr=%llu\n", (unsigned long long)nr);
            break;
    }
}

extern "C" void syscall_isr(cpu_registers_t* regs) {
    syscall_dispatch(regs);
}

void syscall_init() {
    // Allow ring3 to invoke int 0x80: set DPL=3 on gate and register handler
    idt_set_gate(0x80, isr_stub_table[0x80], 0x08, 0xEE); // present | DPL=3 | interrupt gate
    idt_set_handler(0x80, syscall_isr);
} 