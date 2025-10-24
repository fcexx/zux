#include <debug.h>
#include <idt.h>
#include <pic.h>
#include <paging.h>
#include <string.h>
#include <multiboot2.h>
#include <heap.h>
#include <vga.h>
#include <vbe.h>
#include <pit.h>
#include <thread.h>
#include <ata.h>
#include <ps2.h>
#include <iothread.h>
#include <fs_interface.h>
#include <fat32.h>
#include <gdt.h>
#include <syscall.h>
#include <elf.h>
#include <sysinfo.h>
#include <stddef.h>
#include <stdint.h>

char g_tty_private_tag = 0;

// Фреймбуфер инициализируется через vbe_init() в parse_multiboot2

// Запуск интерактивного шелла по умолчанию (busybox sh -i)
extern "C" void start_default_shell();

// Убрано: любые глобалы, связанные с TLS

// Модуль cpio (bzbx), переданный GRUB как Multiboot2 module
static uint64_t g_bzbx_mod_start = 0;
static uint64_t g_bzbx_mod_size  = 0;

extern "C" uint64_t sys_execve(const char* path, const char* const* argv, const char* const* envp);

typedef unsigned int uint32_t;

extern "C" {
        fs_interface_t* fat32_get_interface(void);
}

extern "C" int vfs_mount_from_cpio(const void* data, unsigned long size);
extern "C" fs_interface_t* vfs_get_interface();
// TLS metadata exported by src/fs/elf.cpp
extern "C" uint64_t elf_last_tls_image_vaddr;
extern "C" uint64_t elf_last_tls_filesz;
extern "C" uint64_t elf_last_tls_memsz;
extern "C" uint64_t elf_last_tls_align;

extern "C" void enable_sse() {
        unsigned long cr0, cr4;
        asm volatile ("mov %%cr0, %0" : "=r"(cr0));
        cr0 &= ~(1UL << 2);   // EM=0 (enable FPU instructions)
        cr0 |=  (1UL << 1);   // MP=1 (monitor coprocessor)
        asm volatile ("mov %0, %%cr0" :: "r"(cr0));
    
        asm volatile ("mov %%cr4, %0" : "=r"(cr4));
        cr4 |= (1UL << 9);    // OSFXSR=1 (enable SSE/SSE2 instructions)
        cr4 |= (1UL << 10);   // OSXMMEXCPT=1 (enable unmasked SIMD FP exceptions)
        asm volatile ("mov %0, %%cr4" :: "r"(cr4));
    }

void parse_multiboot2(uint64_t addr) {
        struct multiboot2_tag* tag;
        
        PrintfQEMU("Parsing multiboot2 info at 0x%llx\n", (unsigned long long)addr);
        
        // Кандидаты модулей: приоритетно ищем по cmdline=\"bzbx\", иначе берём первый попавшийся
        uint64_t fb_mod_start = 0, fb_mod_size = 0; bool have_fallback = false; bool picked_bzbx = false;

        for (tag = (struct multiboot2_tag*)(addr + 8);
                 tag->type != 0;
                 tag = (struct multiboot2_tag*)((uint8_t*)tag + ((tag->size + 7) & ~7))) {
                
                PrintfQEMU("Found tag type: %u, size: %u\n", tag->type, tag->size);
                
                switch (tag->type) {
                        case 8: { // Framebuffer
                                struct multiboot2_tag_framebuffer* fb_tag = 
                                        (struct multiboot2_tag_framebuffer*)tag;
                                
                                PrintfQEMU("Framebuffer tag found:\n");
                                PrintfQEMU("  addr: 0x%llx\n", (unsigned long long)fb_tag->framebuffer_addr);
                                PrintfQEMU("  width: %u\n", fb_tag->framebuffer_width);
                                PrintfQEMU("  height: %u\n", fb_tag->framebuffer_height);
                                PrintfQEMU("  pitch: %u\n", fb_tag->framebuffer_pitch);
                                PrintfQEMU("  bpp: %u\n", fb_tag->framebuffer_bpp);
                                // Попробуем предпочесть EDID preferred mode, если GRUB его сообщил через gfxmode.
                                // GRUB с gfxpayload=keep уже устанавливает режим; здесь просто инициализируем VBE.
                                vbe_init((uint64_t)fb_tag->framebuffer_addr,
                                                 fb_tag->framebuffer_width,
                                                 fb_tag->framebuffer_height,
                                                 fb_tag->framebuffer_pitch,
                                                 fb_tag->framebuffer_bpp);
                                break;
                        }
                        case 3: { // Module
                                struct multiboot2_tag_module* m = (struct multiboot2_tag_module*)tag;
                                const char* cmd = (const char*)m->cmdline;
                                uint64_t start = (uint64_t)m->mod_start;
                                uint64_t end   = (uint64_t)m->mod_end;
                                uint64_t size  = (end > start) ? (end - start) : 0;
                                if (size) {
                                        // приоритет: явный модуль с именем/строкой, содержащей "bzbx"
                                        if (!picked_bzbx && cmd && *cmd && strstr(cmd, "bzbx") != nullptr) {
                                                g_bzbx_mod_start = start;
                                                g_bzbx_mod_size  = size;
                                                picked_bzbx = true;
                                        } else if (!have_fallback) {
                                                fb_mod_start = start;
                                                fb_mod_size  = size;
                                                have_fallback = true;
                                        }
                                }
                                break;
                        }
                }
        }

        // Если явный bzbx не найден, но есть любой модуль — используем его как fallback
        if (!picked_bzbx && have_fallback && g_bzbx_mod_size == 0) {
                g_bzbx_mod_start = fb_mod_start;
                g_bzbx_mod_size  = fb_mod_size;
        }
}

static int kexecve(const char* path, const char* const* argv){
        if (!path) return -22;
        uint64_t entry = 0, ustack_top = 0;
        if (elf64_load_process(path, 1 << 20, &entry, &ustack_top) != 0) {
                return -2;
        }
        const int MAX_ARGS = 64;
        const char* kargv_strs[MAX_ARGS];
        size_t kargv_lens[MAX_ARGS];
        int argc = 0;
        if (argv){
                while (argc < MAX_ARGS && argv[argc]){
                        const char* a = argv[argc];
                        size_t alen = strlen(a) + 1;
                        kargv_strs[argc] = a;
                        kargv_lens[argc] = alen;
                        argc++;
                }
        }
        const char env0[] = "PATH=/bin:/usr/bin:/sbin";
        const char env1[] = "HOME=/root";
        const char env2[] = "TERM=linux";
        const char env3[] = "PS1=~ # ";
        uint8_t rnd[16];
        uint64_t t = pit_ticks ? pit_ticks : 0x12345678ULL;
        for (int i=0;i<16;i++){ rnd[i]=(uint8_t)((t>>((i*5)%32))^((uint64_t)(0x9e + 3*i))); }
        // auxv, объявлены в include/elf.h
        uint64_t at_phdr = elf_last_at_phdr;
        uint64_t at_phent = elf_last_at_phent;
        uint64_t at_phnum = elf_last_at_phnum;
        uint64_t at_entry = elf_last_at_entry ? elf_last_at_entry : entry;

        uint64_t sp = ustack_top;
        sp -= sizeof(env3); memcpy((void*)sp, env3, sizeof(env3)); uint64_t e3 = sp;
        sp -= sizeof(env2); memcpy((void*)sp, env2, sizeof(env2)); uint64_t e2 = sp;
        sp -= sizeof(env1); memcpy((void*)sp, env1, sizeof(env1)); uint64_t e1 = sp;
        sp -= sizeof(env0); memcpy((void*)sp, env0, sizeof(env0)); uint64_t e0 = sp;

        uint64_t arg_addrs[MAX_ARGS];
        for (int i = argc - 1; i >= 0; --i){
                size_t len = kargv_lens[i];
                sp -= len; memcpy((void*)sp, kargv_strs[i], len); arg_addrs[i] = sp;
        }

        sp -= sizeof(rnd); memcpy((void*)sp, rnd, sizeof(rnd)); uint64_t at_random_ptr = sp;
        sp &= ~0xFULL;

        // Place execfn string on stack
        size_t execfn_len = strlen(path) + 1;
        sp -= execfn_len; memcpy((void*)sp, path, execfn_len); uint64_t execfn_ptr = sp;
        sp &= ~0xFULL;

        const uint64_t AT_NULL=0, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_PAGESZ=6, AT_BASE=7, AT_ENTRY=9, AT_UID=11, AT_EUID=12, AT_GID=13, AT_EGID=14, AT_CLKTCK=17, AT_RANDOM=25, AT_SECURE=23, AT_EXECFN=31;
        size_t vec_qwords = 1 + (size_t)argc + 1 + 4 + 1 + 2*22;
        sp -= vec_qwords * 8ULL;
        uint64_t* vec = (uint64_t*)sp;
        size_t idx = 0;
        vec[idx++] = (uint64_t)argc;
        for (int i = 0; i < argc; ++i) vec[idx++] = arg_addrs[i];
        vec[idx++] = 0;
        vec[idx++] = e0; vec[idx++] = e1; vec[idx++] = e2; vec[idx++] = e3; vec[idx++] = 0;
        vec[idx++] = AT_PHDR;   vec[idx++] = at_phdr;
        vec[idx++] = AT_PHENT;  vec[idx++] = at_phent;
        vec[idx++] = AT_PHNUM;  vec[idx++] = at_phnum;
        vec[idx++] = AT_ENTRY;  vec[idx++] = at_entry;
        vec[idx++] = AT_PAGESZ; vec[idx++] = 4096;
        vec[idx++] = AT_BASE;   vec[idx++] = 0;
        vec[idx++] = AT_UID;    vec[idx++] = 0;
        vec[idx++] = AT_EUID;   vec[idx++] = 0;
        vec[idx++] = AT_GID;    vec[idx++] = 0;
        vec[idx++] = AT_EGID;   vec[idx++] = 0;
        vec[idx++] = AT_CLKTCK; vec[idx++] = 100;
        vec[idx++] = AT_SECURE; vec[idx++] = 0;
        vec[idx++] = AT_EXECFN; vec[idx++] = execfn_ptr;
        vec[idx++] = AT_RANDOM; vec[idx++] = at_random_ptr;
        vec[idx++] = AT_NULL;   vec[idx++] = 0;

        // Не настраиваем TLS в ядре: это сделает glibc через arch_prctl(ARCH_SET_FS)

        const char* base = path; for (const char* p = path; *p; ++p) if (*p=='/') base = p+1;
        thread_register_user(at_entry, sp, base && *base ? base : "user");
        {
                thread_t* ut = thread_get_current_user();
                if (ut) {
                        extern char g_tty_private_tag;
                        for (int i = 0; i < 3; ++i) ut->fds[i] = nullptr;
                        fs_file_t* f0 = (fs_file_t*)kmalloc(sizeof(fs_file_t)); if (f0){ memset(f0,0,sizeof(*f0)); f0->private_data=&g_tty_private_tag; }
                        fs_file_t* f1 = (fs_file_t*)kmalloc(sizeof(fs_file_t)); if (f1){ memset(f1,0,sizeof(*f1)); f1->private_data=&g_tty_private_tag; }
                        fs_file_t* f2 = (fs_file_t*)kmalloc(sizeof(fs_file_t)); if (f2){ memset(f2,0,sizeof(*f2)); f2->private_data=&g_tty_private_tag; }
                        ut->fds[0]=f0; ut->fds[1]=f1; ut->fds[2]=f2;
                }
        }
        PrintfQEMU("[kexecve] path=%s entry(raw)=0x%llx at_entry=0x%llx rsp=0x%llx\n", path, (unsigned long long)entry, (unsigned long long)at_entry, (unsigned long long)sp);
        asm volatile(
                "xor %%rbx, %%rbx; xor %%rdi, %%rdi; xor %%rsi, %%rsi; xor %%rdx, %%rdx;\n"
                "xor %%r12, %%r12; xor %%r13, %%r13; xor %%r14, %%r14; xor %%r15, %%r15;\n"
                :::"rbx","rdi","rsi","rdx","r12","r13","r14","r15");
        asm volatile("sti");
        enter_user_mode(at_entry, sp);
        return 0;
}

void process_exit() {
        for(;;){ klog_printf("process\n"); }
}

extern "C" void kernel_main(uint32_t multiboot2_magic, uint64_t multiboot2_info_ptr) {
        enable_sse();
        parse_multiboot2(multiboot2_info_ptr);
        
        idt_init();
        pic_init();
        pit_init();
        pic_unmask_irq(0);
        pic_unmask_irq(1);

        paging_init();

        // Сначала инициализируем heap, затем консоль (для VBE backbuffer)
        heap_init();
        if (vbe_is_initialized()) {
                // disable frame showing until early initialization is complete
                vbe_set_present_enabled(0);
                vbec_init_console();
                klog_printf("kernel_main: kernel started with active interrupts (block 0, 1, 14,15 by default)\n");
                klog_printf("framebuffer console %ux%u 16 colors initialized\n\n", vbe_get_width() / 9, vbe_get_height() / 16);
        } else {
                vga_init();
                vga_clear(7, 0);
                klog_printf("vga: text console 80x25 16 colors initialized\n\n");
        }
        ps2_keyboard_init();

        klog_printf("ent!x kernel v0.10.0d\n");
        
        thread_init();
        klog_printf("thread_init: Thread manager is ready\n");
        // swap экрана выполняется только из PIT

        ata_init();
        // Если дисков нет — не ждём ничего от FAT32, работаем с initramfs
        iothread_init();

        gdt_init();
        void* kstack = kmalloc_aligned(16384, 4096);
        if (!kstack) {
                // try plain kmalloc and align the result manually to 4KB
                void* raw = kmalloc(16384 + 4096);
                if (raw) {
                        uint64_t a = (uint64_t)raw;
                        uint64_t aligned = (a + 4095ULL) & ~0xFFFULL;
                        kstack = (void*)aligned;
                        PrintfQEMU("[tss] kmalloc_aligned fallback: raw=%p aligned=%p\n", raw, kstack);
                } else {
                        // Dump heap info to help diagnose why allocation failed
                        dump_heap_info();
                        // Also dump recent allocation history for context
                        extern void dump_alloc_history();
                        dump_alloc_history();
                        klog_printf("fatal: kmalloc_aligned failed; halted\n");
                        for (;;);
                }
        }
        uint64_t kstack_top = (uint64_t)kstack + 16384;
        PrintfQEMU("[tss] kstack=%p kstack_top=0x%llx\n", kstack, (unsigned long long)kstack_top);
        if (kstack) memset(kstack, 0xCD, 16384);
        thread_t* cur = thread_current();
        if (cur) {
                cur->kernel_stack = kstack_top;
        } else {
                PrintQEMU("[tss] WARN: thread_current()==nullptr\n");
        }
        tss_set_rsp0(kstack_top);
        PrintfQEMU("[tss] rsp0 set to 0x%llx\n", (unsigned long long)kstack_top);
        // Обновим стек для входа SYSCALL (используется syscall_entry.S)
        extern uint64_t syscall_kernel_rsp0;
        syscall_kernel_rsp0 = kstack_top;

        syscall_init();
        PrintQEMU("[syscall] init x86_64 SYSCALL...\n");
        syscall_x64_init();
        klog_printf("syscalls: ready to fire\n");
        // Прерывания включим после монтирования VFS, чтобы исключить ранние IRQ во время парсинга cpio
        
        // Initialize and print system information in Unix dmesg style
        sysinfo_init();

        // Если модуль CPIO лежит за пределами ранней identity‑map (например, 0x60000000+),
        // промапим его идентично на время монтирования, затем VFS скопирует данные в heap
        if (g_bzbx_mod_size) {
                uint64_t mb_base = g_bzbx_mod_start & ~0xFFFULL;
                uint64_t mb_end  = (g_bzbx_mod_start + g_bzbx_mod_size + 0xFFFULL) & ~0xFFFULL;
                if (mb_end > mb_base) {
                        uint64_t sz = mb_end - mb_base;
                        paging_map_range(mb_base, mb_base, sz, PAGE_PRESENT | PAGE_WRITABLE);
                        PrintfQEMU("[cpio map] mapped module @0x%llx..0x%llx (%llu KB)\n",
                                   (unsigned long long)mb_base, (unsigned long long)mb_end, (unsigned long long)(sz/1024ULL));
                }
        }

        // Монтируем VFS из модуля Multiboot2, если он передан; иначе — попытка из FAT32
        if (g_bzbx_mod_size) {
                klog_printf("mnt_from_cpio: mounting cpio from module, start=0x%llx size=%llu\n",
                                   (unsigned long long)g_bzbx_mod_start,
                                   (unsigned long long)g_bzbx_mod_size);
                int mrc = vfs_mount_from_cpio((const void*)g_bzbx_mod_start, (unsigned long)g_bzbx_mod_size);
                if (mrc != 0) { klog_printf("vfs: fatal: mount failed, rc=%d\n", mrc); for(;;); }
                fs_interface_t* ifs = vfs_get_interface();
                if (!ifs) { klog_printf("vfs: fatal: interface is null\n"); for(;;); }
                // sanity-check critical ops to avoid jumping through null pointers later
                if (!ifs->open || !ifs->read || !ifs->seek || !ifs->close || !ifs->opendir || !ifs->readdir || !ifs->closedir) {
                        klog_printf("vfs: fatal: interface has null ops\n");
                        for(;;);
                }
        fs_set_current(ifs);
        }
        else { klog_printf("failed to mount cpio module; kernel unable to start"); for (;;); }
        if (vbe_is_initialized()) vbe_set_present_enabled(1);
        asm volatile ("sti");
        const char* argv_fallback[] = { "busybox", "sh", "-i", nullptr };
        //(void)kexecve("/bin/busybox", argv_fallback);
        klog_printf("kexecve: executing busybox shell\n");
        
        // idle kernel process
        int i;
        int j;
        for(;;) {
                if (i % 256) i = 0;
                if (j % 16) j = 0;
                vbec_put_cell(80, 0, '!', j, 0);
                i++;
                j++;
        }
} 

