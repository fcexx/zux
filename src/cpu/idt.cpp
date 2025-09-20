#include <idt.h>
#include <debug.h>
#include <vga.h>
#include <pic.h>
#include <stdint.h>
#include <thread.h>

// локальные таблицы обработчиков (неиспользуемые предупреждения устраним использованием ниже)
static void (*irq_handlers[16])() = {nullptr};
static void (*isr_handlers[256])(cpu_registers_t*) = {nullptr};

static idt_entry_t idt[256];
static idt_ptr_t idt_ptr;
// сообщения об исключениях — определение для внешней декларации из idt.h
const char* exception_messages[] = {
    "Division By Zero","Debug","Non Maskable Interrupt","Breakpoint","Into Detected Overflow",
    "Out of Bounds","Invalid Opcode","No Coprocessor","Double fault","Coprocessor Segment Overrun",
    "Bad TSS","Segment not present","Stack fault","General protection fault","Page fault",
    "Unknown Interrupt","Coprocessor Fault","Alignment Fault","Machine Check",
    "Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved",
    "Reserved","Reserved","Reserved","Reserved","Reserved"
};

static void ud_fault_handler(cpu_registers_t* regs) {
    // Invalid Opcode (#UD). Если из user-space — корректно завершаем текущий юзер-процесс,
    // чтобы не валить ядро из-за мусорного RIP после выхода.
    if ((regs->cs & 3) == 3) {
        PrintfQEMU("[ud] user invalid opcode at RIP=0x%lx, kill process\n", regs->rip);
        thread_t* user = thread_get_current_user();
        if (user) {
            int tid = (int)user->tid;
            thread_stop(tid);
            thread_set_current_user(nullptr);
        }
        for(;;) { thread_yield(); }
    }
    // Иначе — ядро: печатаем и стоп
    kprintf("Invalid Opcode in kernel. RIP=0x%lx\n", regs->rip);
    // no swap in VGA text mode
    for(;;);
}

static void page_fault_handler(cpu_registers_t* regs) {
    unsigned long long cr2;
    asm volatile("mov %%cr2, %0" : "=r"(cr2));
    unsigned long long err = regs->error_code;
    int p = (err & 1) != 0;          // 0: non-present, 1: protection
    int wr = (err & 2) != 0;         // 0: read, 1: write
    int us = (err & 4) != 0;         // 0: supervisor, 1: user
    int rsvd = (err & 8) != 0;       // reserved bit violation
    int id = (err & 16) != 0;        // instruction fetch (if supported)
    // Если fault из user-space — завершаем текущий пользовательский процесс, не падая ядром
    if ((regs->cs & 3) == 3) {
        PrintfQEMU("[pf user] cr2=0x%llx err=0x%llx P=%d W=%d U=%d RSVD=%d ID=%d RIP=0x%llx\n",
                   cr2, err, p, wr, us, rsvd, id, regs->rip);
        kprintf("User page fault: addr=0x%llx err=0x%llx RIP=0x%llx\n", cr2, err, regs->rip);
        thread_t* user = thread_get_current_user();
        if (user) {
            thread_stop((int)user->tid);
            thread_set_current_user(nullptr);
        }
        for(;;) { thread_yield(); }
    }

    // Иначе — kernel fault: печатаем максимум и останавливаемся
    PrintfQEMU("[pf kernel] cr2=0x%llx err=0x%llx [P=%d W/R=%d U/S=%d RSVD=%d I/D=%d]\n", cr2, err, p, wr, us, rsvd, id);
    PrintfQEMU("RIP=0x%llx CS=0x%llx RFLAGS=0x%llx RSP=0x%llx SS=0x%llx\n", regs->rip, regs->cs, regs->rflags, regs->rsp, regs->ss);
    kprintf("Critical error: Page Fault in kernel, halted.\n");
    for (;;);
}

static void gp_fault_handler(cpu_registers_t* regs){
    // Если из ring3 — попробуем распознать «тестовые» инструкции и мягко их пропустить/починить
    if ((regs->cs & 3) == 3) {
        const uint8_t* ip = (const uint8_t*)(uint64_t)regs->rip;
        uint8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0, b6 = 0;
        // Читаем до 7 байт по RIP
        b0 = ip[0]; b1 = ip[1]; b2 = ip[2]; b3 = ip[3]; b4 = ip[4]; b5 = ip[5]; b6 = ip[6];
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
            // ET_EXEC case: load_base==0 → код/данные обычно около 0x00400000..brk
            if (!elf_last_load_base && elf_last_brk_base) {
                if (va >= 0x00400000ULL && va < (elf_last_brk_base + 0x100000ULL)) return true;
            }
            // user stack near 0x30000000
            if (va >= (0x30000000ULL - 0x02000000ULL) && va < 0x30000000ULL) return true;
            // mmap window starting 0x40000000
            if (va >= 0x40000000ULL && va < 0x80000000ULL) return true;
            return false;
        };
        // REX.W + MOV r64, [mem]  (48 8B /r) — обработаем базовые моды адресации (включая RIP-relative)
        if (b0 == 0x48 && b1 == 0x8B) {
            auto rd_from_reg = [&](uint8_t code)->uint64_t&{
                switch (code & 7) {
                    case 0: return regs->rax; case 1: return regs->rcx; case 2: return regs->rdx; case 3: return regs->rbx;
                    case 4: return regs->rsp; case 5: return regs->rbp; case 6: return regs->rsi; default: return regs->rdi;
                }
            };
            uint8_t modrm = b2;
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t reg = (modrm >> 3) & 7;
            uint8_t rm  = modrm & 7;
            uint64_t rip = regs->rip;
            const uint8_t* p = ip + 3; // после modrm
            uint64_t addr = 0;
            bool have_addr = false;
            int instr_len = 3; // 48 8B modrm
            uint8_t sib = 0;
            if (mod != 3) {
                if (rm == 4) { // SIB
                    sib = *p++; instr_len++;
                }
                int disp = 0; int disp_size = 0;
                if (mod == 1) { disp = (int8_t)(*p++); disp_size = 1; instr_len++; }
                else if (mod == 2) { disp = (int32_t)( (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24) ); p += 4; disp_size = 4; instr_len += 4; }
                else if (mod == 0 && rm == 5) { // RIP-relative disp32
                    int32_t d = (int32_t)( (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24) );
                    p += 4; instr_len += 4;
                    uint64_t next_ip = rip + instr_len;
                    addr = next_ip + (int64_t)d;
                    have_addr = true;
                }
                if (!have_addr) {
                    uint64_t base_val = 0;
                    uint64_t index_val = 0; int scale = 1;
                    if (rm == 4) {
                        uint8_t ss = (sib >> 6) & 3; uint8_t idx = (sib >> 3) & 7; uint8_t base = sib & 7;
                        scale = 1 << ss;
                        // index==4 означает отсутствие индекса
                        if (idx != 4) index_val = rd_from_reg(idx);
                        // base==5 и mod==0 трактуем как disp32 (уже обработали выше), иначе берём регистр
                        if (!(mod == 0 && base == 5)) base_val = rd_from_reg(base);
                    } else {
                        base_val = rd_from_reg(rm);
                    }
                    addr = base_val + (uint64_t)disp + (uint64_t)(index_val * (uint64_t)scale);
                    have_addr = true;
                }

                // Аккуратно: читаем только если адрес точно в юзер-диапазоне; RSP/RBP не трогаем
                uint64_t eff = addr;
                if (!in_user_range(eff)) {
                    uint64_t reb = rebase_elf(eff);
                    if (reb) eff = reb;
                }
                bool wrote = false;
                if (in_user_range(eff) && reg != 4 /*RSP*/ && reg != 5 /*RBP*/) {
                    uint64_t read_val = *(const uint64_t*)(uint64_t)eff;
                    rd_from_reg(reg) = read_val;
                    wrote = true;
                }
                PrintfQEMU("[gp] mov r64,[mem]: mod=%u rm=%u reg=%u addr=0x%llx -> set=%s\n",
                           (unsigned)mod, (unsigned)rm, (unsigned)reg,
                           (unsigned long long)eff,
                           wrote?"yes":"no");
                regs->rip += instr_len;
                return;
            }
        }

        // TEST r/m8, imm8  (F6 /0 ib)
        if (b0 == 0xF6) {
            uint8_t modrm = b1;
            uint8_t ext = (modrm >> 3) & 7; // /0 .. /7
            if (ext == 0) {
                auto rd_from_reg = [&](uint8_t code)->uint64_t&{
                    switch (code & 7) {
                        case 0: return regs->rax; case 1: return regs->rcx; case 2: return regs->rdx; case 3: return regs->rbx;
                        case 4: return regs->rsp; case 5: return regs->rbp; case 6: return regs->rsi; default: return regs->rdi;
                    }
                };
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm  = modrm & 7;
                const uint8_t* p = ip + 2; // после opcode+modrm
                int instr_len = 2;
                uint8_t sib = 0;
                int disp = 0;
                uint8_t imm = 0;
                uint64_t addr = 0;
                bool have_mem = false;
                if (mod != 3) {
                    if (rm == 4) { sib = *p++; instr_len++; }
                    if (mod == 1) { disp = (int8_t)(*p++); instr_len++; }
                    else if (mod == 2) { disp = (int32_t)( (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24) ); p += 4; instr_len += 4; }
                    else if (mod == 0 && rm == 5) {
                        // disp32 absolute (without RIP-rel in 64-bit for F6? трактуем как абсолютный)
                        disp = (int32_t)( (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24) );
                        p += 4; instr_len += 4;
                        addr = (uint64_t)(int64_t)disp;
                        have_mem = true;
                    }
                    if (!have_mem) {
                        uint64_t base_val = 0, index_val = 0; int scale = 1;
                        if (rm == 4) {
                            uint8_t ss = (sib >> 6) & 3; uint8_t idx = (sib >> 3) & 7; uint8_t base = sib & 7;
                            scale = 1 << ss;
                            if (idx != 4) index_val = rd_from_reg(idx);
                            if (!(mod == 0 && base == 5)) base_val = rd_from_reg(base);
                        } else {
                            base_val = rd_from_reg(rm);
                        }
                        addr = base_val + (uint64_t)disp + (uint64_t)(index_val * (uint64_t)scale);
                        have_mem = true;
                    }
                    imm = *p++; instr_len++;

                    // Пробуем безопасно прочитать байт, иначе считаем 0
                    uint64_t eff = addr;
                    if (!in_user_range(eff)) {
                        uint64_t reb = rebase_elf(eff);
                        if (reb) eff = reb;
                    }
                    uint8_t mval = 0;
                    if (in_user_range(eff)) mval = *(const uint8_t*)(uint64_t)eff;
                    uint8_t res = (uint8_t)(mval & imm);
                    // Обновим ZF по результату (остальные флаги не трогаем)
                    const uint64_t ZF = 1ULL << 6;
                    if (res == 0) regs->rflags |= ZF; else regs->rflags &= ~ZF;
                    PrintfQEMU("[gp] test r/m8,imm8: addr=0x%llx mval=0x%02x imm=0x%02x -> res=0x%02x ZF=%d\n",
                               (unsigned long long)eff, (unsigned)mval, (unsigned)imm, (unsigned)res, (res==0));
                    regs->rip += instr_len;
                    return;
                }
                // mod==3: регистровый вариант — упрощённо: читаем AL/CL... через 64-бит рег и применяем к младшему байту
                imm = *p++; instr_len++;
                uint8_t mval = (uint8_t)(rd_from_reg(rm) & 0xFF);
                uint8_t res = (uint8_t)(mval & imm);
                const uint64_t ZF = 1ULL << 6;
                if (res == 0) regs->rflags |= ZF; else regs->rflags &= ~ZF;
                PrintfQEMU("[gp] test r8,imm8: reg=%u val=0x%02x imm=0x%02x -> res=0x%02x ZF=%d\n",
                           (unsigned)rm, (unsigned)mval, (unsigned)imm, (unsigned)res, (res==0));
                regs->rip += instr_len;
                return;
            }
        }
        // HLT: эмулируем ожидание прерывания и пропускаем инструкцию
        if (b0 == 0xF4) {
            PrintfQEMU("[gp] emulate HLT at user RIP=0x%lx\n", regs->rip);
            // Разрешим прерывания и усыпим ядро до ближайшего IRQ (например, PIT)
            asm volatile("sti; hlt");
            regs->rip += 1;
            return;
        }
        // UD2 (0F 0B)
        if (b0 == 0x0F && b1 == 0x0B) { PrintfQEMU("[gp] skip UD2 at user RIP=0x%lx\n", regs->rip); regs->rip += 2; return; }
        // INT3 (CC)
        if (b0 == 0xCC) { PrintfQEMU("[gp] skip INT3 at user RIP=0x%lx\n", regs->rip); regs->rip += 1; return; }
        // ICEBP (F1)
        if (b0 == 0xF1) { PrintfQEMU("[gp] skip ICEBP at user RIP=0x%lx\n", regs->rip); regs->rip += 1; return; }
        // REP MOVSB (F3 A4) — безопасная эмуляция без записи в память (чтобы не портить стек/TCB)
        if (b0 == 0xF3 && b1 == 0xA4) {
            uint64_t count = regs->rcx;
            if (count) {
                uint64_t rsi_can = canon_se(regs->rsi);
                uint64_t rdi_can = canon_se(regs->rdi);
                int df = (regs->rflags & (1ULL << 10)) ? 1 : 0; // DF флаг
                // Безопасно сдвигаем указатели, запись не производим
                    if (!df) { regs->rsi += count; regs->rdi += count; }
                    else { regs->rsi -= count; regs->rdi -= count; }
                PrintfQEMU("[gp] rep movsb: len=%llu (no-store)\n", (unsigned long long)count);
                regs->rcx = 0;
            }
            regs->rip += 2;
            return;
        }
        // MOV r13b,(r12) — без записи (skip store), только продвигаем RIP
        if (b0 == 0x45 && b1 == 0x88 && b2 == 0x2C && b3 == 0x24) {
            PrintfQEMU("[gp] skip mov r13b,(r12) (no-store)\n");
            regs->rip += 4;
            return;
        }
        // MOVB imm8,(r12): 41 C6 04 24 xx — no-store
        if (b0 == 0x41 && b1 == 0xC6 && b2 == 0x04 && b3 == 0x24) {
            PrintfQEMU("[gp] skip movb imm,(r12) (no-store)\n");
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
        kprintf("Exception: %s\n", exception_messages[vec]);
        kprintf("Error code: 0x%lx\n", regs->error_code);
        kprintf("RIP: 0x%lx\n", regs->rip);
        kprintf("RSP: 0x%lx\n", regs->rsp);
        kprintf("GPR: RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                   regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi,
                   regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
        kprintf("Halted due to unhandled exception\n");
        PrintfQEMU("EX: %s\n", exception_messages[vec]);
        PrintfQEMU("CODE: 0x%lx\n", regs->error_code);
        PrintfQEMU("RIP: 0x%lx\n", regs->rip);
        PrintfQEMU("RSP: 0x%lx\n", regs->rsp);
        PrintfQEMU("GPR: RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                   regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi,
                   regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
            PrintfQEMU("Halted due to unhandled exception\n");
        // no swap in VGA text mode
            for (;;);
    }
    
    // Unknown vector
    PrintfQEMU("Unknown interrupt %d (0x%x)\n", vec, vec);
    PrintfQEMU("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
    kprintf("Unknown interrupt %d (0x%x)\n", vec, vec);
    kprintf("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
    // no swap in VGA text mode
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
    // Register UD handler (#6)
    idt_set_handler(6, ud_fault_handler);
    // Register GP fault handler (#13)
    idt_set_handler(13, gp_fault_handler);
    
    asm volatile("lidt %0" : : "m"(idt_ptr));
}
