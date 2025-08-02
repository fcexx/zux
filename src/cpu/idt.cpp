#include "idt.h"
#include "debug.h"
#include "pic.h"

static void (*irq_handlers[16])() = {nullptr};
static void (*isr_handlers[256])(cpu_registers_t*) = {nullptr};

static idt_entry_t idt[256];
static idt_ptr_t idt_ptr;

extern "C" void isr_dispatch(cpu_registers_t* regs) {
    if (isr_handlers[regs->interrupt_number]) {
        isr_handlers[regs->interrupt_number](regs);
    } else {
        if (regs->interrupt_number < 32) {
            PrintfQEMU("Exception: %s\n", exception_messages[regs->interrupt_number]);
            PrintfQEMU("Error code: 0x%lx\n", regs->error_code);
            PrintfQEMU("RIP: 0x%lx\n", regs->rip);
            PrintfQEMU("RSP: 0x%lx\n", regs->rsp);
            for (;;);
        } else {
            PrintfQEMU("Unknown interrupt %d (0x%x)\n", regs->interrupt_number, regs->interrupt_number);
            PrintfQEMU("RIP: 0x%lx, RSP: 0x%lx\n", regs->rip, regs->rsp);
            for (;;);
        }
    }

    if (regs->interrupt_number >= 32 && regs->interrupt_number <= 47) {
        PrintfQEMU("IRQ %d (vector %d) handled\n", regs->interrupt_number - 32, regs->interrupt_number);
        pic_send_eoi(regs->interrupt_number - 32);
    }
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
    
    asm volatile("lidt %0" : : "m"(idt_ptr));
    PrintQEMU("IDT initialized\n");
}
