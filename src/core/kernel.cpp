#include <debug.h>
#include <idt.h>
#include <pic.h>
#include <paging.h>
#include <string.h>
#include <multiboot2.h>
#include <heap.h>
#include <vga.h>
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
#include <stddef.h>

char g_tty_private_tag = 0;

// Вернём переменные фреймбуфера, чтобы код, завязанный на них, компилировался
extern "C" {
    uint32_t* framebuffer_addr = 0;
    uint32_t fb_height = 0;
    uint32_t fb_pitch = 0;
}

// Запуск интерактивного шелла по умолчанию (busybox sh -i)
extern "C" void start_default_shell();

// Глобальный адрес AT_RANDOM из пользовательского стека, используется для TLS canary
uint64_t g_at_random_ptr = 0;

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
    const char env0[] = "PATH=/bin:/usr/bin";
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

    const uint64_t AT_NULL=0, AT_PAGESZ=6, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_ENTRY=9, AT_RANDOM=25;
    size_t vec_qwords = 1 + (size_t)argc + 1 + 4 + 1 + 2*7;
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
    vec[idx++] = AT_RANDOM; vec[idx++] = at_random_ptr;
    vec[idx++] = AT_NULL;   vec[idx++] = 0;

    uint64_t tls_va = (ustack_top & ~0xFFFFFULL) - 0x1000ULL;
    void* tls_page = kmalloc(0x2000);
    if (tls_page) {
        uint64_t tls_phys = ((uint64_t)tls_page + 0xFFFULL) & ~0xFFFULL;
        paging_map_page(tls_va, tls_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
        memset((void*)tls_va, 0, 0x1000);
    }

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
    // Сохраним AT_RANDOM для последующей инициализации TLS canary
    // Сохраним адрес AT_RANDOM для инициализации TLS canary в arch_prctl
    extern uint64_t g_at_random_ptr;
    g_at_random_ptr = at_random_ptr;
    PrintfQEMU("[kexecve] path=%s entry(raw)=0x%llx at_entry=0x%llx rsp=0x%llx at_random=0x%llx\n", path, (unsigned long long)entry, (unsigned long long)at_entry, (unsigned long long)sp, (unsigned long long)g_at_random_ptr);
    asm volatile(
        "xor %%rbx, %%rbx; xor %%rdi, %%rdi; xor %%rsi, %%rsi; xor %%rdx, %%rdx;\n"
        "xor %%r12, %%r12; xor %%r13, %%r13; xor %%r14, %%r14; xor %%r15, %%r15;\n"
        :::"rbx","rdi","rsi","rdx","r12","r13","r14","r15");
    asm volatile("sti");
    enter_user_mode(at_entry, sp);
    return 0;
}

extern "C" void kernel_main(uint32_t multiboot2_magic, uint64_t multiboot2_info_ptr) {
    enable_sse();
    parse_multiboot2(multiboot2_info_ptr);
    
    idt_init();
    pic_init();
    pit_init();
    pic_unmask_irq(0);
    pic_unmask_irq(1);
    pic_unmask_irq(14);
    pic_unmask_irq(15);
    
    // 砥 ࠭  ࠭ 맮
    paging_init();

    // ���� ������� �३����� (��᫥ parse_multiboot2/vbe_init, �� ��� ����㯠)
    if (false && framebuffer_addr && fb_height && fb_pitch) {
        uint64_t fb_start = (uint64_t)framebuffer_addr;
        uint64_t fb_size  = (uint64_t)fb_height * (uint64_t)fb_pitch;
        // ВЫРАВНИВАНИЕ ПО 4К СТРАНИЦЕ, а не на 16 байт
        uint64_t map_start = fb_start & ~0xFFFULL;                      // align down to 4K
        uint64_t map_end   = (fb_start + fb_size + 0xFFFULL) & ~0xFFFULL; // align up to 4K
        uint64_t map_size  = map_end - map_start;
        PrintfQEMU("[fbmap] fb_start=0x%llx size=%llu map_start=0x%llx map_size=%llu\n",
                   (unsigned long long)fb_start,
                   (unsigned long long)fb_size,
                   (unsigned long long)map_start,
                   (unsigned long long)map_size);
        paging_map_range(map_start, map_start, map_size, PAGE_PRESENT | PAGE_WRITABLE);
    }

    heap_init();
    vga_init();

    ps2_keyboard_init();

    vga_clear(15, 0);

    kprintf("Solar kernel v0.10.0d\n");
    kprintf("VGA text console 80x25 initialized\n\n");
    
    thread_init();

    // swap экрана выполняется только из PIT

    ata_init();
    iothread_init();

    // swap экрана выполняется только из PIT

    // ���樠�����㥬 䠩����� ��⥬� ⮫쪮 ��᫥ ATA
    kprintf("fat32: Initializing filesystem...\n");
    fs_interface_t* fat32_interface = fat32_get_interface();
    if (fs_init(fat32_interface) == 0) {
        kprintf("fat32: Filesystem initialized successfully\n");
    } else {
        kprintf("fat32: Failed to initialize filesystem\n");
    }          

    // swap экрана выполняется только из PIT

    // ���樠������ GDT/TSS
    gdt_init();
    // �뤥�塞 � ����ࠨ���� kernel-�⥪ ��� �������� (current) ��⮪�, ���� �� ���室� �� ring3 �� IRQ �㤥� �㫥��� rsp0
    void* kstack = kmalloc_aligned(16384, 4096);
    if (!kstack) {
        kprintf("fatal: kmalloc_aligned failed; halted");
        for (;;);
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
 
     // Инициализация системных вызовов (int 0x80 и путь x86_64 SYSCALL)
     PrintQEMU("[syscall] init int80...\n");
     syscall_init();
     PrintQEMU("[syscall] init x86_64 SYSCALL...\n");
     syscall_x64_init();
     kprintf("syscalls: ready to fire\n");
    

    // Монтируем VFS из модуля Multiboot2, если он передан; иначе — попытка из FAT32
    if (g_bzbx_mod_size) {
        kprintf("Mounting cpio from module: start=0x%llx size=%llu\n",
                   (unsigned long long)g_bzbx_mod_start,
                   (unsigned long long)g_bzbx_mod_size);
        vfs_mount_from_cpio((const void*)g_bzbx_mod_start, (unsigned long)g_bzbx_mod_size);
        fs_set_current(vfs_get_interface());
    }
    else { kprintf("Failed to mount busybox module; kernel unable to start"); for (;;); }

    kprintf("\nSolar kernel v.0.10.0 (demo) without init script\n");
    // Запускаем начальный шелл
    const char* argv_fallback[] = { "busybox", "sh", "-i", nullptr };
    (void)kexecve("/bin/busybox", argv_fallback);

    

    // Если пользовательский процесс завершился/упал, попытаться перезапустить шелл
    for(;;) {
        thread_t* u = thread_get_current_user();
        if (!u) {
            const char* argv2[] = { "busybox", "sh", "-i", nullptr };
            kprintf("User task ended. Restarting shell...\n");
            (void)kexecve("/bin/busybox", argv2);
        }
        asm volatile("hlt");
    }
} 