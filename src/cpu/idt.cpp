#include <idt.h>
#include <debug.h>
#include <pic.h>

static void (*irq_handlers[16])() = {nullptr};
static void (*isr_handlers[256])(cpu_registers_t*) = {nullptr};

static idt_entry_t idt[256];
static idt_ptr_t idt_ptr;

static void page_fault_handler(cpu_registers_t* regs) {
    unsigned long long cr2;
    asm volatile("mov %%cr2, %0" : "=r"(cr2));
    unsigned long long err = regs->error_code;
    int p = (err & 1) != 0;          // 0: non-present, 1: protection
    int wr = (err & 2) != 0;         // 0: read, 1: write
    int us = (err & 4) != 0;         // 0: supervisor, 1: user
    int rsvd = (err & 8) != 0;       // reserved bit violation
    int id = (err & 16) != 0;        // instruction fetch (if supported)
    PrintfQEMU("PAGE FAULT: cr2=0x%x err=0x%x [P=%d W/R=%d U/S=%d RSVD=%d I/D=%d]\n", cr2, err, p, wr, us, rsvd, id);
    PrintfQEMU("RIP=0x%x CS=0x%x RFLAGS=0x%x RSP=0x%x SS=0x%x\n", regs->rip, regs->cs, regs->rflags, regs->rsp, regs->ss);
    PrintfQEMU("RAX=0x%x RBX=0x%x RCX=0x%x RDX=0x%x RSI=0x%x RDI=0x%x\n",
               regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi);
    PrintfQEMU("R8=0x%x R9=0x%x R10=0x%x R11=0x%x R12=0x%x R13=0x%x R14=0x%x R15=0x%x\n",
               regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
    for (;;);
}

extern "C" void isr_dispatch(cpu_registers_t* regs) {
    uint8_t vec = (uint8_t)regs->interrupt_number;

    // IRQ 32..47: EOI required
    if (vec >= 32 && vec <= 47) {
        if (isr_handlers[vec]) {
            isr_handlers[vec](regs);
        } else {
            PrintfQEMU("Unhandled IRQ %d\n", vec - 32);
        }
        pic_send_eoi(vec - 32);
        return;
    }

    // Any other vector: call registered handler if present (e.g., int 0x80)
    if (isr_handlers[vec]) {
        isr_handlers[vec](regs);
        return;
    }

    // Exceptions 0..31 without specific handler: print and halt
    if (vec < 32) {
        PrintfQEMU("Exception: %s\n", exception_messages[vec]);
        PrintfQEMU("Error code: 0x%lx\n", regs->error_code);
        PrintfQEMU("RIP: 0x%lx\n", regs->rip);
        PrintfQEMU("RSP: 0x%lx\n", regs->rsp);
        PrintfQEMU("GPR: RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                   regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi,
                   regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
        PrintfQEMU("Halted due to unhandled exception\n");
        for (;;);
    }

    // Unknown vector
    PrintfQEMU("Unknown interrupt %d (0x%x)\n", vec, vec);
    PrintfQEMU("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
    for (;;);
}

void idt_set_gate(uint8_t num, uint64_t handler, uint16_t selector, uint8_t flags) {
    idt[num].offset_low = handler & 0xFFFF;
    idt[num].offset_mid = (handler >> 16) & 0xFFFF;
    idt[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
    idt[num].selector = selector;
    idt[num].ist = 0;
    idt[num].flags = flags;
    idt[num].reserved = 0;
}

void idt_set_handler(uint8_t num, void (*handler)(cpu_registers_t*)) {
    isr_handlers[num] = handler;
}

void idt_init() {
    idt_ptr.limit = sizeof(idt) - 1;
    idt_ptr.base = (uint64_t)&idt;

    for (int i = 0; i < 256; i++) {
        idt_set_gate(i, isr_stub_table[i], 0x08, 0x8E);
    }

    // Register detailed page fault handler
    idt_set_handler(14, page_fault_handler);

    asm volatile("lidt %0" : : "m"(idt_ptr));
}
