#include <idt.h>
#include <debug.h>
#include <vga.h>
#include <vbe.h>
#include <pic.h>
#include <pit.h>
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

static inline void read_crs(uint64_t* cr0, uint64_t* cr2, uint64_t* cr3, uint64_t* cr4){
        uint64_t t0=0,t2=0,t3=0,t4=0; (void)t0; (void)t2; (void)t3; (void)t4;
        asm volatile("mov %%cr0, %0" : "=r"(t0));
        asm volatile("mov %%cr2, %0" : "=r"(t2));
        asm volatile("mov %%cr3, %0" : "=r"(t3));
        asm volatile("mov %%cr4, %0" : "=r"(t4));
        if (cr0) *cr0 = t0; if (cr2) *cr2 = t2; if (cr3) *cr3 = t3; if (cr4) *cr4 = t4;
}

static void dump(const char* what, const char* who, cpu_registers_t* regs, uint64_t cr2, uint64_t err, bool user_mode){
        // Header
        klog_printf("BUG: unable to handle %s paging request at %016llx\n", who, (unsigned long long)cr2);
        klog_printf("#PF: error_code=0x%llx P=%d W=%d U=%d RSVD=%d ID=%d\n", (unsigned long long)err,
                    (int)((err&1)!=0),(int)((err&2)!=0),(int)((err&4)!=0),(int)((err&8)!=0),(int)((err&16)!=0));
        klog_printf("Oops: 0000 [#1] SMP\n");
        // RIP/RSP like Linux
        klog_printf("RIP: 0010:[<%016llx>] %s\n", (unsigned long long)regs->rip, what);
        klog_printf("RSP: %04llx:%016llx  EFLAGS: %08llx\n",
                    (unsigned long long)regs->cs, (unsigned long long)regs->rsp, (unsigned long long)regs->rflags);
        // GPRs
        klog_printf("RAX: %016llx RBX: %016llx RCX: %016llx RDX: %016llx\n",
                    regs->rax, regs->rbx, regs->rcx, regs->rdx);
        klog_printf("RSI: %016llx RDI: %016llx RBP: %016llx R08: %016llx\n",
                    regs->rsi, regs->rdi, regs->rbp, regs->r8);
        klog_printf("R09: %016llx R10: %016llx R11: %016llx R12: %016llx\n",
                    regs->r9, regs->r10, regs->r11, regs->r12);
        klog_printf("R13: %016llx R14: %016llx R15: %016llx\n",
                    regs->r13, regs->r14, regs->r15);
        // Control regs
        uint64_t c0=0,c2=cr2,c3=0,c4=0; read_crs(&c0,&c2,&c3,&c4);
        klog_printf("FS: 0000  GS: 0000  DS: 0000  ES: 0000  CR0: %016llx\n", (unsigned long long)c0);
        klog_printf("CR2: %016llx CR3: %016llx CR4: %016llx\n", (unsigned long long)c2, (unsigned long long)c3, (unsigned long long)c4);
        // Minimal call trace (stack dump)
        klog_printf("Call Trace:\n");
        uint64_t* sp = (uint64_t*)(uint64_t)regs->rsp; const int max = 10;
        for (int i=0;i<max;i++){
                uint64_t v = sp[i];
                klog_printf(" [<%016llx>] ?\n", (unsigned long long)v);
        }
        // Tail
        if (user_mode) klog_printf("End of user trace.\n"); else klog_printf("kernel panic: %s\n", what);
}

static void ud_fault_handler(cpu_registers_t* regs) {
        // Invalid Opcode (#UD). В ring3 не эмулируем — завершаем поток.
        if ((regs->cs & 3) == 3) {
                qemu_log_printf("[ud] user invalid opcode at RIP=0x%lx\n", regs->rip);
                dump("invalid opcode", "user", regs, 0, 0, true);
                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                for(;;){ thread_yield(); }
        }
        // Иначе — ядро: печатаем и стоп
        if (vbe_is_initialized()) vbe_force_unlock();
        dump("invalid opcode", "kernel", regs, 0, 0, false);
        qemu_log_printf("[ud regs] rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx\n",
                           regs->rax, regs->rbx, regs->rcx, regs->rdx);
        qemu_log_printf("[ud regs] rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx\n",
                           regs->rsi, regs->rdi, regs->rbp, regs->rsp);
        qemu_log_printf("[ud misc] rip=0x%llx cs=0x%llx rflags=0x%llx ss=0x%llx\n",
                           regs->rip, regs->cs, regs->rflags, regs->ss);
        // Попробуем вывести 32 байта кода вокруг RIP
        const uint8_t* ip = (const uint8_t*)(uint64_t)regs->rip;
        uint8_t code[32];
        for (int i=0;i<32;i++){ code[i] = ip[i]; }
        qemu_log_printf("[ud code] ");
        for (int i=0;i<32;i++){ qemu_log_printf("%02x ", (unsigned)code[i]); }
        qemu_log_printf("\n");
        dump("invalid opcode", "kernel", regs, 0, 0, false);
        for(;;){ asm volatile("sti; hlt":::"memory"); }
}

// Handle Divide-by-zero (INT 0). For user faults: kill process and return to idle;
// for kernel faults: print diagnostics and halt.
static void div_zero_handler(cpu_registers_t* regs) {
        qemu_log_printf("[div0] divide by zero at RIP=0x%llx err=0x%llx\n", (unsigned long long)regs->rip, (unsigned long long)regs->error_code);
        // If fault originated from user mode, terminate the user process safely
        if ((regs->cs & 3) == 3) {
                dump("divide by zero", "user", regs, 0, regs->error_code, true);
                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                // leave CPU in idle loop to avoid returning into faulty user code
                for(;;){ asm volatile("sti; hlt" ::: "memory"); }
        }
        // Kernel fault: print and halt
        dump("divide by zero", "kernel", regs, 0, regs->error_code, false);
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

static void page_fault_handler(cpu_registers_t* regs) {
    // Никакого рендера/свапа из обработчика PF
        unsigned long long cr2;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        unsigned long long err = regs->error_code;
        // Fast sanity: if registers are clearly invalid (null RIP or tiny RSP), avoid heavy dumps
        // and drop to idle to prevent kernel from dereferencing bad user pointers.
        if (regs->rip == 0 || regs->rsp < 0x1000) {
                qemu_log_printf("[pf] invalid user regs detected RIP=0x%llx RSP=0x%llx; dropping to idle\n",
                               (unsigned long long)regs->rip, (unsigned long long)regs->rsp);
                if (vbe_is_initialized()) vbe_force_unlock();
                for(;;){ asm volatile("sti; hlt" ::: "memory"); }
        }
        int p = (err & 1) != 0;                  // 0: non-present, 1: protection
        int wr = (err & 2) != 0;                 // 0: read, 1: write
        int us = (err & 4) != 0;                 // 0: supervisor, 1: user
        int rsvd = (err & 8) != 0;           // reserved bit violation
        int id = (err & 16) != 0;                // instruction fetch (if supported)
        // Если fault из user-space — завершаем текущий пользовательский процесс, не падая ядром
        if ((regs->cs & 3) == 3) {
                // Quick sanity: if registers look clearly corrupted (RIP==0 or tiny RSP),
                // avoid attempting to read user memory or stop a non-existent process —
                // just idle to avoid crashing the kernel further.
                if (regs->rip == 0 || regs->rsp < 0x1000) {
                        qemu_log_printf("[pf] user PF with invalid regs RIP=0x%llx RSP=0x%llx; dropping to idle\n", (unsigned long long)regs->rip, (unsigned long long)regs->rsp);
                        if (vbe_is_initialized()) vbe_force_unlock();
                        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
                }
                // If there is no registered current_user (possible during early init or corrupted state),
                // treat this as a kernel fault to avoid dereferencing user pointers or attempting to stop
                // a non-existent process which may lead to further undefined behavior.
                if (thread_get_current_user() == nullptr) {
                        qemu_log_printf("[pf] user-mode PF but no current_user; treating as orphaned user context, entering idle\n");
                        if (vbe_is_initialized()) vbe_force_unlock();
                        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
                }
                qemu_log_printf("[pf user] cr2=0x%llx err=0x%llx P=%d W=%d U=%d RSVD=%d ID=%d RIP=0x%llx\n",
                                   cr2, err, p, wr, us, rsvd, id, regs->rip);
                dump("user space fault", "user", regs, cr2, err, true);

                // Дополнительный детальный дамп (безопасно, с защитой от рекурсивного дампа)
                static int pf_dumping = 0;
                if (!pf_dumping) {
                        pf_dumping = 1;
                        extern uint64_t elf_last_load_base;
                        extern uint64_t elf_last_brk_base;
                        qemu_log_printf("[pf dump] elf_load=0x%llx elf_brk=0x%llx (addrs: &load=0x%llx &brk=0x%llx)\n",
                                           (unsigned long long)elf_last_load_base, (unsigned long long)elf_last_brk_base,
                                           (unsigned long long)&elf_last_load_base, (unsigned long long)&elf_last_brk_base);
                        // Print current user process info if available
                        thread_t* tcur = thread_get_current_user();
                        if (tcur) {
                                qemu_log_printf("[pf userinfo] pid=%d name=%s rsp=0x%llx rip_expected=0x%llx\n",
                                                   (int)tcur->tid, tcur->name, (unsigned long long)tcur->user_stack, (unsigned long long)tcur->user_rip);
                        } else {
                                qemu_log_printf("[pf userinfo] no registered current_user\n");
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
                                qemu_log_printf("[pf dump] NOTICE: elf_last_* appear ascii-like, dumping nearby memory for diagnosis\n");
                                // Dump 64 bytes around each variable address (if readable)
                                const unsigned char* p_load = (const unsigned char*)((uint64_t)&elf_last_load_base - 32);
                                qemu_log_printf("[mem dump] around &elf_last_load_base=0x%llx:\n", (unsigned long long)(unsigned long long)&elf_last_load_base);
                                for (int i = 0; i < 64; i += 8) {
                                        qemu_log_printf("  %02x%02x%02x%02x%02x%02x%02x%02x ",
                                                           p_load[i+0], p_load[i+1], p_load[i+2], p_load[i+3], p_load[i+4], p_load[i+5], p_load[i+6], p_load[i+7]);
                                        qemu_log_printf("\n");
                                }
                                const unsigned char* p_brk = (const unsigned char*)((uint64_t)&elf_last_brk_base - 32);
                                qemu_log_printf("[mem dump] around &elf_last_brk_base=0x%llx:\n", (unsigned long long)(unsigned long long)&elf_last_brk_base);
                                for (int i = 0; i < 64; i += 8) {
                                        qemu_log_printf("  %02x%02x%02x%02x%02x%02x%02x%02x ",
                                                           p_brk[i+0], p_brk[i+1], p_brk[i+2], p_brk[i+3], p_brk[i+4], p_brk[i+5], p_brk[i+6], p_brk[i+7]);
                                        qemu_log_printf("\n");
                                }
                        }
                        // Печатаем регистры
                        qemu_log_printf("[pf regs] rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx\n",
                                           regs->rax, regs->rbx, regs->rcx, regs->rdx);
                        qemu_log_printf("[pf regs] rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx\n",
                                           regs->rsi, regs->rdi, regs->rbp, regs->rsp);
                        qemu_log_printf("[pf regs] r15=0x%llx r14=0x%llx r13=0x%llx r12=0x%llx\n",
                                           regs->r15, regs->r14, regs->r13, regs->r12);
                        qemu_log_printf("[pf misc] rip=0x%llx cs=0x%llx rflags=0x%llx ss=0x%llx\n",
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
                                qemu_log_printf("[pf code] ");
                                for (int i = 0; i < 32; ++i) qemu_log_printf("%02x ", (unsigned)code[i]);
                                qemu_log_printf("\n");
                        } else {
                                qemu_log_printf("[pf code] RIP not in known user ranges, skipping code dump\n");
                        }

                        // Печать нескольких слов со стека
                        if (in_user_range_simple((uint64_t)regs->rsp)) {
                                uint64_t* sp = (uint64_t*)(uint64_t)regs->rsp;
                                qemu_log_printf("[pf stack] ");
                                for (int i = 0; i < 8; ++i) {
                                        uint64_t v = sp[i];
                                        qemu_log_printf("0x%llx ", v);
                                }
                                qemu_log_printf("\n");
                        }
                        pf_dumping = 0;
                }

                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                // Разблокируем VBE CS флаг, если кто-то держал его при входе в fault, чтобы курсор продолжал мигать
                if (vbe_is_initialized()) vbe_force_unlock();
                // Не возвращаемся в тот же пользовательский контекст (иначе мгновенный повторный PF)
                // Уходим в idle-петлю: PIT продолжит тикать, курсор мигает
                for(;;){ asm volatile("sti; hlt" ::: "memory"); }
        }
kernel_fault:
    // Никакого рендера/свапа из обработчика PF
        // Иначе — kernel fault: печатаем максимум и не блокируем PIT, чтобы курсор продолжал мигать
        dump("kernel page fault", "kernel", regs, cr2, err, false);
        klog_printf("Rebooting in 5 seconds...\n");
        if (vbe_is_initialized()) vbe_force_unlock();
        pit_sleep_ms(5000);
        kprintf("Reboot");
        // Avoid console output here to prevent re-entrant faults
        // Разрешаем прерывания и уходим в HLT‑петлю: PIT продолжит тикать и курсор будет мигать
        for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

static void gp_fault_handler(cpu_registers_t* regs){
    // Никакого рендера/свапа из обработчика GP
        // Строгая семантика для POSIX-подобного поведения: никаких эмуляций в ring3.
        // General Protection Fault в пользовательском процессе рассматривается как фатальная ошибка процесса.
        if ((regs->cs & 3) == 3) {
                qemu_log_printf("[gp] user GP: RIP=0x%lx ERR=0x%lx RCX=0x%llx RSP=0x%llx\n",
                                   regs->rip, regs->error_code, regs->rcx, regs->rsp);
                qemu_log_printf("[gp regs] RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx\n",
                                   regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi);
                qemu_log_printf("[gp regs] R8 =0x%llx R9 =0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                                   regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
                qemu_log_printf("[gp rbx diag] saved_in=0x%llx saved_out=0x%llx\n",
                                   (unsigned long long)dbg_saved_rbx_in, (unsigned long long)dbg_saved_rbx_out);
                // Выведем FS селектор и базу (MSR IA32_FS_BASE), а также эффективный адрес для FS:[RCX]
                uint64_t fs_base_lo, fs_base_hi, fs_base;
                asm volatile("rdmsr" : "=a"(*(uint32_t*)&fs_base_lo), "=d"(*(uint32_t*)&fs_base_hi) : "c"(0xC0000100));
                fs_base = (fs_base_hi << 32) | (fs_base_lo & 0xFFFFFFFFu);
                uint16_t fs_sel; asm volatile("mov %%fs, %0" : "=r"(fs_sel));
                uint64_t eff = fs_base + (uint64_t)regs->rcx;
                qemu_log_printf("[gp fs] sel=0x%hx base=0x%llx eff(fs+rcx)=0x%llx\n",
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
                        qemu_log_printf("[gp code] ");
                        for (int i = 0; i < 32; ++i) qemu_log_printf("%02x ", (unsigned)code[i]);
                        qemu_log_printf("\n");
                } else {
                        qemu_log_printf("[gp code] RIP not in known user ranges, skipping code dump\n");
                }

                // Печать нескольких слов со стека
                if (in_user_range_simple((uint64_t)regs->rsp)) {
                        uint64_t* sp = (uint64_t*)(uint64_t)regs->rsp;
                        qemu_log_printf("[gp stack] ");
                        for (int i = 0; i < 8; ++i) {
                                uint64_t v = sp[i];
                                qemu_log_printf("0x%llx ", v);
                        }
                        qemu_log_printf("\n");
                }
                thread_t* user = thread_get_current_user();
                if (user) {
                        thread_stop((int)user->tid);
                        thread_set_current_user(nullptr);
                }
                for(;;){ thread_yield(); }
        }
        // kernel GP — стоп, но оставляем PIT активным для мигания курсора
        dump("general protection", "kernel", regs, 0, regs->error_code, false);
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

static void df_fault_handler(cpu_registers_t* regs){
        // Double Fault (#DF) — используем отдельный IST стек, чтобы избежать triple fault
        klog_printf("Double fault: RIP=0x%llx RSP=0x%llx ERR=0x%llx\n", (unsigned long long)regs->rip,
                    (unsigned long long)regs->rsp, (unsigned long long)regs->error_code);
        // Минимальный дамп
        qemu_log_printf("[df] RIP=0x%llx RSP=0x%llx CS=0x%llx SS=0x%llx RFLAGS=0x%llx\n",
                        (unsigned long long)regs->rip, (unsigned long long)regs->rsp,
                        (unsigned long long)regs->cs, (unsigned long long)regs->ss,
                        (unsigned long long)regs->rflags);
        // Застываем в безопасной петле с включёнными прерываниями
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
                        qemu_log_printf("Unhandled IRQ %d\n", vec - 32);
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
                qemu_log_printf("EX: %s\n", exception_messages[vec]);
                qemu_log_printf("CODE: 0x%lx\n", regs->error_code);
                qemu_log_printf("RIP: 0x%lx\n", regs->rip);
                qemu_log_printf("RSP: 0x%lx\n", regs->rsp);
                qemu_log_printf("GPR: RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx RSI=0x%llx RDI=0x%llx R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                                   regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi,
                                   regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
                        qemu_log_printf("Halted due to unhandled exception\n");
                // no swap in VGA text mode
                        for (;;);
        }
        
        // Unknown vector
        qemu_log_printf("Unknown interrupt %d (0x%x)\n", vec, vec);
        qemu_log_printf("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
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
        // Register divide-by-zero handler (#0)
        idt_set_handler(0, div_zero_handler);
        // Register UD handler (#6)
        idt_set_handler(6, ud_fault_handler);
        // Register GP fault handler (#13)
        idt_set_handler(13, gp_fault_handler);
        // Register DF handler (#8) and put it on IST1
        idt_set_handler(8, df_fault_handler);
        // Пометим IST=1 у вектора 8
        idt[8].ist = 1;
        
        asm volatile("lidt %0" : : "m"(idt_ptr));
}
