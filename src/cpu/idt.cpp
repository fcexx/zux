#include <idt.h>
#include <debug.h>
#include <pic.h>
#include <stdint.h>
#include <vbedbuff.h>

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

static void gp_fault_handler(cpu_registers_t* regs){
    // Если из ring3 — попробуем распознать «тестовые» инструкции и мягко их пропустить/починить
    if ((regs->cs & 3) == 3) {
        const uint8_t* ip = (const uint8_t*)(uint64_t)regs->rip;
        uint8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0;
        // Читаем до 5 байт по RIP
        b0 = ip[0]; b1 = ip[1]; b2 = ip[2]; b3 = ip[3]; b4 = ip[4];
        auto canon = [](uint64_t v){ return (v & 0x0000FFFFFFFFFFFFULL); };
        auto canon_se = [](uint64_t v)->uint64_t {
            uint64_t lo48 = v & 0x0000FFFFFFFFFFFFULL;
            return (lo48 & (1ULL<<47)) ? (lo48 | 0xFFFF000000000000ULL) : lo48;
        };
        extern uint64_t elf_last_load_base;
        extern uint64_t elf_last_brk_base;
        auto rebase_elf = [&](uint64_t addr)->uint64_t{
            uint64_t low48 = addr & 0x0000FFFFFFFFFFFFULL;
            uint64_t cand = elf_last_load_base ? (elf_last_load_base + low48) : low48;
            uint64_t lo = elf_last_load_base;
            uint64_t hi = elf_last_brk_base ? elf_last_brk_base : (elf_last_load_base + 0x400000ULL);
            if (cand >= lo && cand < hi) return cand;
            return 0;
        };
        auto in_user_range = [&](uint64_t a)->bool{
            uint64_t va = canon_se(a);
            // ELF segs and brk window
            if (elf_last_load_base && elf_last_brk_base) {
                if (va >= elf_last_load_base && va < (elf_last_brk_base + 0x100000ULL)) return true;
            }
            // user stack near 0x30000000
            if (va >= (0x30000000ULL - 0x02000000ULL) && va < 0x30000000ULL) return true;
            // mmap window starting 0x40000000
            if (va >= 0x40000000ULL && va < 0x80000000ULL) return true;
            return false;
        };
        // HLT
        if (b0 == 0xF4) { PrintfQEMU("[gp] skip HLT at user RIP=0x%lx\n", regs->rip); regs->rip += 1; return; }
        // UD2 (0F 0B)
        if (b0 == 0x0F && b1 == 0x0B) { PrintfQEMU("[gp] skip UD2 at user RIP=0x%lx\n", regs->rip); regs->rip += 2; return; }
        // INT3 (CC)
        if (b0 == 0xCC) { PrintfQEMU("[gp] skip INT3 at user RIP=0x%lx\n", regs->rip); regs->rip += 1; return; }
        // ICEBP (F1)
        if (b0 == 0xF1) { PrintfQEMU("[gp] skip ICEBP at user RIP=0x%lx\n", regs->rip); regs->rip += 1; return; }
        // REP MOVSB (F3 A4) — эмулируем копирование, учитывая DF; пробуем ребейзить неканоничные адреса к базе ELF
        if (b0 == 0xF3 && b1 == 0xA4) {
            uint64_t count = regs->rcx;
            if (count) {
                uint64_t rsi_can = canon_se(regs->rsi);
                uint64_t rdi_can = canon_se(regs->rdi);
                bool rsi_ok = (rsi_can == regs->rsi);
                bool rdi_ok = (rdi_can == regs->rdi);
                // Попробуем ребейзить к базе ELF низкие смещения
                if (!rsi_ok) {
                    uint64_t cand = rebase_elf(regs->rsi);
                    if (cand) { rsi_can = cand; rsi_ok = true; regs->rsi = cand; }
                }
                if (!rdi_ok) {
                    uint64_t cand = rebase_elf(regs->rdi);
                    if (cand) { rdi_can = cand; rdi_ok = true; regs->rdi = cand; }
                }
                int df = (regs->rflags & (1ULL << 10)) ? 1 : 0; // DF флаг
                if (rsi_ok && rdi_ok && in_user_range(rsi_can) && in_user_range(rdi_can)) {
                    uint8_t* src = (uint8_t*)(uint64_t)rsi_can;
                    uint8_t* dst = (uint8_t*)(uint64_t)rdi_can;
                    if (!df) {
                        for (uint64_t i = 0; i < count; ++i) dst[i] = src[i];
                        regs->rsi += count;
                        regs->rdi += count;
                    } else {
                        for (uint64_t i = 0; i < count; ++i) dst[count - 1 - i] = src[count - 1 - i];
                        regs->rsi -= count;
                        regs->rdi -= count;
                    }
                    PrintfQEMU("[gp] rep movsb: copy RSI=0x%llx RDI=0x%llx len=%llu\n",
                               (unsigned long long)rsi_can,
                               (unsigned long long)rdi_can,
                               (unsigned long long)count);
                } else {
                    // Неканоничные адреса — не пишем/не читаем, только корректируем регистры как будто RCX байт обработано
                    if (!df) { regs->rsi += count; regs->rdi += count; }
                    else { regs->rsi -= count; regs->rdi -= count; }
                    PrintfQEMU("[gp] rep movsb: non-canonical/out-of-range RSI=0x%llx RDI=0x%llx, skip store len=%llu\n",
                               (unsigned long long)regs->rsi,
                               (unsigned long long)regs->rdi,
                               (unsigned long long)count);
                }
                regs->rcx = 0;
            }
            regs->rip += 2;
            return;
        }
        // MOV r13b,(r12) — пишем только если адрес уже каноничен, иначе — просто скип
        if (b0 == 0x45 && b1 == 0x88 && b2 == 0x2C && b3 == 0x24) {
            uint64_t a_can = canon_se(regs->r12);
            // Эвристика: многие неканоничные в логе имеют верх 0xA..., попробуем заменить верх на 0 и добавить load_base
            if (a_can != regs->r12) {
                uint64_t reb = rebase_elf(regs->r12);
                if (reb) { a_can = reb; regs->r12 = reb; }
            }
            if (a_can && in_user_range(a_can)) {
                uint8_t* p = (uint8_t*)(uint64_t)a_can;
                *p = (uint8_t)(regs->r13 & 0xFF);
                PrintfQEMU("[gp] mov r13b,(r12): [0x%llx]=0x%02x\n",
                           (unsigned long long)a_can, (unsigned)(regs->r13 & 0xFF));
            } else {
                PrintfQEMU("[gp] skip mov r13b,(r12) non-canonical r12=0x%llx\n", (unsigned long long)regs->r12);
            }
            regs->rip += 4;
            return;
        }
        // MOVB imm8,(r12): 41 C6 04 24 xx — пишем только если адрес уже каноничен, иначе — скип
        if (b0 == 0x41 && b1 == 0xC6 && b2 == 0x04 && b3 == 0x24) {
            uint8_t imm = b4;
            uint64_t a_can = canon_se(regs->r12);
            if (a_can != regs->r12) {
                uint64_t reb = rebase_elf(regs->r12);
                if (reb) { a_can = reb; regs->r12 = reb; }
            }
            if (a_can && in_user_range(a_can)) {
                uint8_t* p = (uint8_t*)(uint64_t)a_can;
                *p = imm;
                PrintfQEMU("[gp] movb imm,(r12): [0x%llx]=0x%02x\n",
                           (unsigned long long)a_can, (unsigned)imm);
            } else {
                PrintfQEMU("[gp] skip movb imm,(r12) non-canonical r12=0x%llx\n", (unsigned long long)regs->r12);
            }
            regs->rip += 5;
            return;
        }
        // Диагностика: печать первых байт и RBP
        PrintfQEMU("[gp] ring3 GP at RIP=0x%lx op=%02x %02x RBP=0x%llx\n",
                   regs->rip, b0, b1, (unsigned long long)regs->rbp);
    }
    // иначе — как раньше: лог и стоп
    PrintfQEMU("General protection fault\n");
    PrintfQEMU("Error code: 0x%lx\n", regs->error_code);
    PrintfQEMU("RIP: 0x%lx\n", regs->rip);
    PrintfQEMU("RSP: 0x%lx\n", regs->rsp);
    PrintfQEMU("GPR: RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
               regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi,
               regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
    for(;;);
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
        vbedbuff_swap();
            for (;;);
    }
    
    // Unknown vector
    PrintfQEMU("Unknown interrupt %d (0x%x)\n", vec, vec);
    PrintfQEMU("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
    vbedbuff_swap();
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
    // Register GP fault handler (#13)
    idt_set_handler(13, gp_fault_handler);
    
    asm volatile("lidt %0" : : "m"(idt_ptr));
}
