#include <idt.h>
#include <debug.h>
#include <vga.h>
#include <vbe.h>
#include <pic.h>
#include <stdint.h>
#include <thread.h>
#include <stdint.h>
#include <stddef.h>
// Avoid including <cstdint> because cross-toolchain headers may not provide it; use uint64_t instead

// Forward declare C-linkage helpers from other compilation units
extern "C" void dump_alloc_history();
extern "C" uint64_t dbg_saved_rbx_in;
extern "C" uint64_t dbg_saved_rbx_out;

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
        // Invalid Opcode (#UD). В ring3 не эмулируем — завершаем поток.
        if ((regs->cs & 3) == 3) {
                PrintfQEMU("[ud] user invalid opcode at RIP=0x%lx\n", regs->rip);
                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                for(;;){ thread_yield(); }
        }
        // Иначе — ядро: печатаем и стоп
        if (vbe_is_initialized()) vbe_swap();
        kprintf("Invalid Opcode in kernel. RIP=0x%lx\n", regs->rip);
        PrintfQEMU("[ud regs] rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx\n",
                           regs->rax, regs->rbx, regs->rcx, regs->rdx);
        PrintfQEMU("[ud regs] rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx\n",
                           regs->rsi, regs->rdi, regs->rbp, regs->rsp);
        PrintfQEMU("[ud misc] rip=0x%llx cs=0x%llx rflags=0x%llx ss=0x%llx\n",
                           regs->rip, regs->cs, regs->rflags, regs->ss);
        // Попробуем вывести 32 байта кода вокруг RIP
        const uint8_t* ip = (const uint8_t*)(uint64_t)regs->rip;
        uint8_t code[32];
        for (int i=0;i<32;i++){ code[i] = ip[i]; }
        PrintfQEMU("[ud code] ");
        for (int i=0;i<32;i++){ PrintfQEMU("%02x ", (unsigned)code[i]); }
        PrintfQEMU("\n");
        for(;;){ asm volatile("sti; hlt":::"memory"); }
}

static void page_fault_handler(cpu_registers_t* regs) {
    // Никакого рендера/свапа из обработчика PF
        unsigned long long cr2;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        unsigned long long err = regs->error_code;
        int p = (err & 1) != 0;                  // 0: non-present, 1: protection
        int wr = (err & 2) != 0;                 // 0: read, 1: write
        int us = (err & 4) != 0;                 // 0: supervisor, 1: user
        int rsvd = (err & 8) != 0;           // reserved bit violation
        int id = (err & 16) != 0;                // instruction fetch (if supported)
        // Если fault из user-space — завершаем текущий пользовательский процесс, не падая ядром
        if ((regs->cs & 3) == 3) {
                PrintfQEMU("[pf user] cr2=0x%llx err=0x%llx P=%d W=%d U=%d RSVD=%d ID=%d RIP=0x%llx\n",
                                   cr2, err, p, wr, us, rsvd, id, regs->rip);
                kprintf("User page fault: addr=0x%llx err=0x%llx RIP=0x%llx\n", cr2, err, regs->rip);

                // Дополнительный детальный дамп (безопасно, с защитой от рекурсивного дампа)
                static int pf_dumping = 0;
                if (!pf_dumping) {
                        pf_dumping = 1;
                        extern uint64_t elf_last_load_base;
                        extern uint64_t elf_last_brk_base;
                        PrintfQEMU("[pf dump] elf_load=0x%llx elf_brk=0x%llx (addrs: &load=0x%llx &brk=0x%llx)\n",
                                           (unsigned long long)elf_last_load_base, (unsigned long long)elf_last_brk_base,
                                           (unsigned long long)&elf_last_load_base, (unsigned long long)&elf_last_brk_base);
                        // Print current user process info if available
                        thread_t* tcur = thread_get_current_user();
                        if (tcur) {
                                PrintfQEMU("[pf userinfo] pid=%d name=%s rsp=0x%llx rip_expected=0x%llx\n",
                                                   (int)tcur->tid, tcur->name, (unsigned long long)tcur->user_stack, (unsigned long long)tcur->user_rip);
                        } else {
                                PrintfQEMU("[pf userinfo] no registered current_user\n");
                        }
                        // Если переменные содержат явно текстовые данные — предполагаем повреждение и обнуляем, чтобы
                        // дальнейшая логика не полагалась на мусорные значения.
                        auto looks_like_ascii = [&](uint64_t v)->bool{
                                int printable = 0;
                                for (int i = 0; i < 8; ++i) {
                                        unsigned char c = (unsigned char)((v >> (i*8)) & 0xFF);
                                        if (c >= 32 && c < 127) printable++;
                                }
                                return printable >= 4; // если >=4 байт печатаемые — вероятно строка
                        };
                        if (looks_like_ascii(elf_last_load_base) || looks_like_ascii(elf_last_brk_base)) {
                                PrintfQEMU("[pf dump] NOTICE: elf_last_* appear ascii-like, dumping nearby memory for diagnosis\n");
                                // Dump 64 bytes around each variable address (if readable)
                                const unsigned char* p_load = (const unsigned char*)((uint64_t)&elf_last_load_base - 32);
                                PrintfQEMU("[mem dump] around &elf_last_load_base=0x%llx:\n", (unsigned long long)(unsigned long long)&elf_last_load_base);
                                for (int i = 0; i < 64; i += 8) {
                                        PrintfQEMU("  %02x%02x%02x%02x%02x%02x%02x%02x ",
                                                           p_load[i+0], p_load[i+1], p_load[i+2], p_load[i+3], p_load[i+4], p_load[i+5], p_load[i+6], p_load[i+7]);
                                        PrintfQEMU("\n");
                                }
                                const unsigned char* p_brk = (const unsigned char*)((uint64_t)&elf_last_brk_base - 32);
                                PrintfQEMU("[mem dump] around &elf_last_brk_base=0x%llx:\n", (unsigned long long)(unsigned long long)&elf_last_brk_base);
                                for (int i = 0; i < 64; i += 8) {
                                        PrintfQEMU("  %02x%02x%02x%02x%02x%02x%02x%02x ",
                                                           p_brk[i+0], p_brk[i+1], p_brk[i+2], p_brk[i+3], p_brk[i+4], p_brk[i+5], p_brk[i+6], p_brk[i+7]);
                                        PrintfQEMU("\n");
                                }
                        }
                        // Печатаем регистры
                        PrintfQEMU("[pf regs] rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx\n",
                                           regs->rax, regs->rbx, regs->rcx, regs->rdx);
                        PrintfQEMU("[pf regs] rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx\n",
                                           regs->rsi, regs->rdi, regs->rbp, regs->rsp);
                        PrintfQEMU("[pf regs] r15=0x%llx r14=0x%llx r13=0x%llx r12=0x%llx\n",
                                           regs->r15, regs->r14, regs->r13, regs->r12);
                        PrintfQEMU("[pf misc] rip=0x%llx cs=0x%llx rflags=0x%llx ss=0x%llx\n",
                                           regs->rip, regs->cs, regs->rflags, regs->ss);

                        // Попробуем напечатать несколько байт вокруг RIP (если RIP в ожидаемом user-диапазоне)
                        auto in_user_range_simple = [&](uint64_t va)->bool{
                                uint64_t v = va;
                                if (elf_last_load_base && elf_last_brk_base) {
                                        if (v >= elf_last_load_base && v < (elf_last_brk_base + 0x100000ULL)) return true;
                                }
                                // If we only know brk base
                                if (!elf_last_load_base && elf_last_brk_base) {
                                        if (v >= 0x00400000ULL && v < (elf_last_brk_base + 0x100000ULL)) return true;
                                }
                                // If ELF heuristics are not set yet, fall back to a reasonable user-code window
                                if (!elf_last_load_base && !elf_last_brk_base) {
                                        if (v >= 0x00400000ULL && v < 0x04000000ULL) return true; // 4..64MB
                                }
                                if (v >= (0x30000000ULL - 0x02000000ULL) && v < 0x30000000ULL) return true;
                                if (v >= 0x40000000ULL && v < 0x80000000ULL) return true;
                                return false;
                        };

                        if (in_user_range_simple((uint64_t)regs->rip)) {
                                const uint8_t* ip = (const uint8_t*)(uint64_t)regs->rip;
                                uint8_t code[32];
                                for (int i = 0; i < 32; ++i) {
                                        // Берём по одному байту; если чтение вызовет новый PF, он будет обработан рекурсивно,
                                        // но мы ограничили глубину pf_dumping, поэтому не зациклится
                                        code[i] = ip[i];
                                }
                                PrintfQEMU("[pf code] ");
                                for (int i = 0; i < 32; ++i) PrintfQEMU("%02x ", (unsigned)code[i]);
                                PrintfQEMU("\n");
                        } else {
                                PrintfQEMU("[pf code] RIP not in known user ranges, skipping code dump\n");
                        }

                        // Печать нескольких слов со стека
                        if (in_user_range_simple((uint64_t)regs->rsp)) {
                                uint64_t* sp = (uint64_t*)(uint64_t)regs->rsp;
                                PrintfQEMU("[pf stack] ");
                                for (int i = 0; i < 8; ++i) {
                                        uint64_t v = sp[i];
                                        PrintfQEMU("0x%llx ", v);
                                }
                                PrintfQEMU("\n");
                        }
                        pf_dumping = 0;
                }

                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                // Возвращаемся к планировщику вместо бесконечного цикла
                //thread_yield();
                return;
        }
    // Никакого рендера/свапа из обработчика PF
        // Иначе — kernel fault: печатаем максимум и не блокируем PIT, чтобы курсор продолжал мигать
        PrintfQEMU("[pf kernel] cr2=0x%llx err=0x%llx [P=%d W/R=%d U/S=%d RSVD=%d I/D=%d]\n", cr2, err, p, wr, us, rsvd, id);
        PrintfQEMU("RIP=0x%llx CS=0x%llx RFLAGS=0x%llx RSP=0x%llx SS=0x%llx\n", regs->rip, regs->cs, regs->rflags, regs->rsp, regs->ss);
        // Avoid console output here to prevent re-entrant faults
        // Разрешаем прерывания и уходим в HLT‑петлю: PIT продолжит тикать и курсор будет мигать
        for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

static void gp_fault_handler(cpu_registers_t* regs){
    // Никакого рендера/свапа из обработчика GP
        // Строгая семантика для POSIX-подобного поведения: никаких эмуляций в ring3.
        // General Protection Fault в пользовательском процессе рассматривается как фатальная ошибка процесса.
        if ((regs->cs & 3) == 3) {
                PrintfQEMU("[gp] user GP: RIP=0x%lx ERR=0x%lx RCX=0x%llx RSP=0x%llx\n",
                                   regs->rip, regs->error_code, regs->rcx, regs->rsp);
                PrintfQEMU("[gp regs] RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx\n",
                                   regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi);
                PrintfQEMU("[gp regs] R8 =0x%llx R9 =0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                                   regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
                PrintfQEMU("[gp rbx diag] saved_in=0x%llx saved_out=0x%llx\n",
                                   (unsigned long long)dbg_saved_rbx_in, (unsigned long long)dbg_saved_rbx_out);
                // Выведем FS селектор и базу (MSR IA32_FS_BASE), а также эффективный адрес для FS:[RCX]
                uint64_t fs_base_lo, fs_base_hi, fs_base;
                asm volatile("rdmsr" : "=a"(*(uint32_t*)&fs_base_lo), "=d"(*(uint32_t*)&fs_base_hi) : "c"(0xC0000100));
                fs_base = (fs_base_hi << 32) | (fs_base_lo & 0xFFFFFFFFu);
                uint16_t fs_sel; asm volatile("mov %%fs, %0" : "=r"(fs_sel));
                uint64_t eff = fs_base + (uint64_t)regs->rcx;
                PrintfQEMU("[gp fs] sel=0x%hx base=0x%llx eff(fs+rcx)=0x%llx\n",
                                   fs_sel, (unsigned long long)fs_base, (unsigned long long)eff);
                // Дополнительная диагностика похожая на page fault: дамп окрестности RIP и вершины стека,
                // стараемся читать только в ожидаемых user-диапазонах, чтобы не получить повторный PF
                extern uint64_t elf_last_load_base;
                extern uint64_t elf_last_brk_base;
                auto in_user_range_simple = [&](uint64_t va)->bool{
                        uint64_t v = va;
                        if (elf_last_load_base && elf_last_brk_base) {
                                if (v >= elf_last_load_base && v < (elf_last_brk_base + 0x100000ULL)) return true;
                        }
                        if (!elf_last_load_base && elf_last_brk_base) {
                                if (v >= 0x00400000ULL && v < (elf_last_brk_base + 0x100000ULL)) return true;
                        }
                        if (!elf_last_load_base && !elf_last_brk_base) {
                                if (v >= 0x00400000ULL && v < 0x04000000ULL) return true; // 4..64MB
                        }
                        if (v >= (0x30000000ULL - 0x02000000ULL) && v < 0x30000000ULL) return true; // near user stack
                        if (v >= 0x40000000ULL && v < 0x80000000ULL) return true; // mmap window
                        return false;
                };

                // Печать нескольких байт вокруг RIP
                if (in_user_range_simple((uint64_t)regs->rip)) {
                        const uint8_t* ip = (const uint8_t*)(uint64_t)regs->rip;
                        uint8_t code[32];
                        for (int i = 0; i < 32; ++i) code[i] = ip[i];
                        PrintfQEMU("[gp code] ");
                        for (int i = 0; i < 32; ++i) PrintfQEMU("%02x ", (unsigned)code[i]);
                        PrintfQEMU("\n");
                } else {
                        PrintfQEMU("[gp code] RIP not in known user ranges, skipping code dump\n");
                }

                // Печать нескольких слов со стека
                if (in_user_range_simple((uint64_t)regs->rsp)) {
                        uint64_t* sp = (uint64_t*)(uint64_t)regs->rsp;
                        PrintfQEMU("[gp stack] ");
                        for (int i = 0; i < 8; ++i) {
                                uint64_t v = sp[i];
                                PrintfQEMU("0x%llx ", v);
                        }
                        PrintfQEMU("\n");
                }
                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                for(;;){ thread_yield(); }
        }
        // kernel GP — стоп, но оставляем PIT активным для мигания курсора
        PrintfQEMU("General protection fault in kernel\n");
        PrintfQEMU("Error code: 0x%lx RIP=0x%lx RSP=0x%lx\n", regs->error_code, regs->rip, regs->rsp);
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

extern "C" void isr_dispatch(cpu_registers_t* regs) {
        uint8_t vec = (uint8_t)regs->interrupt_number;

        // Если пришёл IRQ1 (клавиатура) — гарантируем EOI даже при отсутствии обработчика
        if (vec == 33) {
                if (isr_handlers[vec]) {
                        isr_handlers[vec](regs);
                }
                pic_send_eoi(1);
                return;
        }

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
