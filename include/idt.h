#pragma once

#include <stdint.h>

typedef struct {
    uint64_t interrupt_number;      // номер вектора прерывания
    uint64_t error_code;    // код ошибки (или 0)
    // Сохранённые регистры CPU
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
    // Сохранённые аппаратные значения
    uint64_t rip, cs, rflags, rsp, ss;
} cpu_registers_t;

struct idt_entry_t {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t flags;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

struct idt_ptr_t {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

extern "C" {
    extern uint64_t isr_stub_table[];
    void isr_dispatch(cpu_registers_t* regs);
}

static const char* exception_messages[] = {
    "Division By Zero",
    "Debug",
    "Non Maskable Interrupt",
    "Breakpoint",
    "Into Detected Overflow",
    "Out of Bounds",
    "Invalid Opcode",
    "No Coprocessor",
    "Double fault",
    "Coprocessor Segment Overrun",
    "Bad TSS",
    "Segment not present",
    "Stack fault",
    "General protection fault",
    "Page fault",
    "Unknown Interrupt",
    "Coprocessor Fault",
    "Alignment Fault",
    "Machine Check", 
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved"
};

void idt_init();
void idt_set_gate(uint8_t num, uint64_t handler, uint16_t selector, uint8_t flags);
void idt_set_handler(uint8_t num, void (*handler)(cpu_registers_t*));
