#include <debug.h>
#include <idt.h>
#include <pic.h>
#include <paging.h>
#include <string.h>
#include <multiboot2.h>
#include <heap.h>
#include <pit.h>
#include <vbe.h>
#include <vbedbuff.h>
#include <vbetty.h>
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

extern "C" char g_tty_private_tag = 0;

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
                
                vbe_init(fb_tag->framebuffer_addr, 
                        fb_tag->framebuffer_width, 
                        fb_tag->framebuffer_height, 
                        fb_tag->framebuffer_pitch, 
                        fb_tag->framebuffer_bpp);
                break;
            }
        }
    }
}

void test_thread() {
    while (1);
}

// �ਬ�� �㭪樨 ��� �⥭�� ᮤ�ন���� �����
void list_directory_contents(const char* path) {
    
    if (!path) {
        kprintf("Error: null path\n");
        return;
    }
    
    kprintf("Listing directory: %s\n", path);
    
    // �஢��塞, ���樠����஢��� �� 䠩����� ��⥬�
    if (!fs_is_initialized()) {
        kprintf("Filesystem not initialized\n");
        return;
    }
    
    // ���뢠�� ��४���
    fs_dir_t* dir = fs_opendir(path);
    
    if (!dir) {
        kprintf("Failed to open directory: %s\n", path);
        return;
    }

    kprintf("Directory opened successfully\n");
    
    fs_dirent_t entry;
    int count = 0;
    
    // ��⠥� �� ����� � ��४�ਨ � ��࠭�祭���
    while (count < 10) {
        int result = fs_readdir(dir, &entry);
        
        if (result != 0) {
            // ����� ��� ����ᥩ ��� �ந��諠 �訡��
            break;
        }
        
        count++;
        
        // �஢��塞, �� ��� �� ���⮥
        if (entry.name[0] == '\0') {
            continue;
        }

        // ��।��塞 ⨯ �����
        const char* type = (entry.attributes & FS_ATTR_DIRECTORY) ? "DIR" : "FILE";
        
        // �뢮��� ���ଠ�� � 䠩��/�����
        kprintf(" [%s] %s", type, entry.name);
        
        // �᫨ �� 䠩�, �����뢠�� ࠧ���
        if (!(entry.attributes & FS_ATTR_DIRECTORY)) {
            kprintf(" (%u bytes)", (unsigned int)entry.size);
        }
        
        kprintf("\n");
    }
    
    kprintf("total %d\n", count);
    
    // ����뢠�� ��४���
    fs_closedir(dir);
}


// user_demo 㤠��: ����� ����㦠�� ELF �� 䠩����� ��⥬�

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
    if (framebuffer_addr && fb_height && fb_pitch) {
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
    vbedbuff_init();
    vbetty_init();

    ps2_keyboard_init();

    vbedbuff_clear(0x000000);
    vbetty_set_bg_color(0x000000);
    vbetty_set_fg_color(0xC4C4C4);

    kprintf("\nLoading Solar...\n\n");
    kprintf("Successfully loaded 100x75 VBE terminal (800x600x4, 32 bit color et al.)\n\n");
    
    thread_init();

    vbedbuff_swap();

    ata_init();
    iothread_init();

    vbedbuff_swap();

    // ���樠�����㥬 䠩����� ��⥬� ⮫쪮 ��᫥ ATA
    kprintf("fat32: Initializing filesystem...\n");
    fs_interface_t* fat32_interface = fat32_get_interface();
    if (fs_init(fat32_interface) == 0) {
        kprintf("fat32: Filesystem initialized successfully\n");
    } else {
        kprintf("fat32: Failed to initialize filesystem\n");
    }          

    vbedbuff_swap();

    // ���樠������ GDT/TSS
    gdt_init();
    // �뤥�塞 � ����ࠨ���� kernel-�⥪ ��� �������� (current) ��⮪�, ���� �� ���室� �� ring3 �� IRQ �㤥� �㫥��� rsp0
    void* kstack = kmalloc_aligned(16384, 4096);
    if (!kstack) {
        PrintQEMU("[tss] kmalloc_aligned(16K) failed\n");
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
     PrintQEMU("[syscall] init done\n");
     vbedbuff_swap();
 
    kprintf("OS is ready\n\n");

    // Подключаем VFS из /boot/bzbx (cpio newc)
    {
        fs_file_t* bz = fs_open("/boot/bzbx", FS_OPEN_READ);
        if (bz) {
            // читаем файл целиком в память
            uint64_t sz = bz->size;
            uint8_t* buf = (uint8_t*)kmalloc(sz);
            int total = 0;
            while ((uint64_t)total < sz) {
                int chunk = fs_read(bz, buf + total, (sz - total) > 4096 ? 4096 : (int)(sz - total));
                if (chunk <= 0) break;
                total += chunk;
            }
            if (total == (int)sz) {
                vfs_mount_from_cpio(buf, sz);
                fs_set_current(vfs_get_interface());
                PrintQEMU("[init] switched to VFS (cpio)\n");
                // debug: list VFS content
                list_directory_contents("/");
                list_directory_contents("/bin");
            } else {
                PrintQEMU("[init] failed to read /boot/bzbx\n");
            }
            fs_close(bz);
        } else {
            PrintQEMU("[init] /boot/bzbx not found\n");
        }
    }

    // Попытка выполнить /start как init: читаем /start, передаём в busybox sh -c
    {
        uint64_t elf_entry = 0, ustack_top = 0;
        if (elf64_load_process("/bin/busybox", 1 << 20, &elf_entry, &ustack_top) == 0) {
            // Прочитаем /start из VFS
            char* script_buf = nullptr;
            uint64_t script_len = 0;
            {
                fs_file_t* sf = fs_open("/start", FS_OPEN_READ);
                if (sf) {
                    script_len = sf->size;
                    if (script_len > 4096) script_len = 4096; // ограничим для простоты
                    script_buf = (char*)kmalloc(script_len + 1);
                    if (script_buf) {
                        int rd = fs_read(sf, script_buf, (int)script_len);
                        if (rd < 0) rd = 0;
                        script_buf[rd] = '\0';
                        script_len = (uint64_t)rd;
                    }
                    fs_close(sf);
                }
            }
            // Сформировать стек для argv=["sh","-c",script], envп, auxv
            uint64_t sp = ustack_top;
            const char arg0[] = "sh";
            const char arg1[] = "-c";
            const char* arg2 = script_buf ? script_buf : ". /start; exec sh -i";
            // env
            const char env0[] = "PATH=/bin:/usr/bin";
            const char env1[] = "HOME=/root";
            const char env2[] = "TERM=linux";
            const char env3[] = "PS1=~ # ";

            // Копируем строки (env, затем argv) на вершину стека (вниз)
            sp -= sizeof(env3); memcpy((void*)sp, env3, sizeof(env3)); uint64_t e3 = sp;
            sp -= sizeof(env2); memcpy((void*)sp, env2, sizeof(env2)); uint64_t e2 = sp;
            sp -= sizeof(env1); memcpy((void*)sp, env1, sizeof(env1)); uint64_t e1 = sp;
            sp -= sizeof(env0); memcpy((void*)sp, env0, sizeof(env0)); uint64_t e0 = sp;
            size_t arg2_len = strlen(arg2) + 1;
            sp -= arg2_len; memcpy((void*)sp, arg2, arg2_len); uint64_t a2 = sp;
            sp -= sizeof(arg1); memcpy((void*)sp, arg1, sizeof(arg1)); uint64_t a1 = sp;
            sp -= sizeof(arg0); memcpy((void*)sp, arg0, sizeof(arg0)); uint64_t a0 = sp;
            // AT_RANDOM
            uint8_t rnd[16];
            uint64_t t = pit_ticks ? pit_ticks : 0x12345678ULL;
            for (int i=0;i<16;i++){ rnd[i]=(uint8_t)((t>>((i*5)%32))^((uint64_t)(0x9e + 3*i))); }
            sp -= sizeof(rnd); memcpy((void*)sp, rnd, sizeof(rnd)); uint64_t at_random_ptr = sp;
            sp &= ~0xFULL;
            const uint64_t AT_NULL=0, AT_PAGESZ=6, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_ENTRY=9, AT_RANDOM=25;
            extern uint64_t elf_last_at_phdr, elf_last_at_phent, elf_last_at_phnum, elf_last_at_entry;
            uint64_t at_phdr = elf_last_at_phdr;
            uint64_t at_phent = elf_last_at_phent;
            uint64_t at_phnum = elf_last_at_phnum;
            uint64_t at_entry = elf_last_at_entry;
            // Вектор: argc, argv*, NULL, envп, NULL, auxv
            uint64_t vec[] = {
                3, a0, a1, a2, 0,
                e0, e1, e2, e3, 0,
                AT_PHDR, at_phdr,
                AT_PHENT, at_phent,
                AT_PHNUM, at_phnum,
                AT_ENTRY, at_entry,
                AT_PAGESZ, 4096,
                AT_RANDOM, at_random_ptr,
                AT_NULL, 0
            };
            sp -= sizeof(vec); memcpy((void*)sp, vec, sizeof(vec));
            // TLS страница (как раньше)
            uint64_t tls_va = (ustack_top & ~0xFFFFFULL) - 0x1000ULL;
            void* tls_page = kmalloc(0x2000);
            if (tls_page) {
                uint64_t tls_phys = ((uint64_t)tls_page + 0xFFFULL) & ~0xFFFULL;
                paging_map_page(tls_va, tls_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
                memset((void*)tls_va, 0, 0x1000);
            }
            thread_register_user(elf_entry, sp, "init");
            // init stdio as /dev/tty
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
            PrintfQEMU("[enter_user] rip=0x%llx rsp=0x%llx cs=0x%x ss=0x%x\n",
                       (unsigned long long)elf_entry,
                       (unsigned long long)sp,
                       (unsigned)USER_CS,
                       (unsigned)USER_DS);
            asm volatile(
                "xor %%rbx, %%rbx; xor %%rdi, %%rdi; xor %%rsi, %%rsi; xor %%rdx, %%rdx;\n"
                "xor %%r12, %%r12; xor %%r13, %%r13; xor %%r14, %%r14; xor %%r15, %%r15;\n"
                :::"rbx","rdi","rsi","rdx","r12","r13","r14","r15");
            asm volatile("sti");
            enter_user_mode(elf_entry, sp);
        }
    }

    // Если сюда дошли — fallback на старый путь /bin/sh
    uint64_t elf_entry = 0, ustack_top = 0;
    PrintfQEMU("Loading /bin/sh...\n");
    if (elf64_load_process("/bin/sh", 1 << 20, &elf_entry, &ustack_top) == 0) {
        // Сформировать стек для argv=["sh","/start"], envp=NULL, auxv
        uint64_t sp = ustack_top;
        const char arg0[] = "sh";
        const char arg1[] = "/start";
        sp -= sizeof(arg1); memcpy((void*)sp, arg1, sizeof(arg1)); uint64_t a1 = sp;
        sp -= sizeof(arg0); memcpy((void*)sp, arg0, sizeof(arg0)); uint64_t a0 = sp;
        // AT_RANDOM
        uint8_t rnd[16];
        uint64_t t = pit_ticks ? pit_ticks : 0x12345678ULL;
        for (int i=0;i<16;i++){ rnd[i]=(uint8_t)((t>>((i*5)%32))^((uint64_t)(0x9e + 3*i))); }
        sp -= sizeof(rnd); memcpy((void*)sp, rnd, sizeof(rnd)); uint64_t at_random_ptr = sp;
        sp &= ~0xFULL;
        const uint64_t AT_NULL=0, AT_PAGESZ=6, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_ENTRY=9, AT_RANDOM=25;
        uint64_t at_phdr = (0x20000000ULL) + 64; // предположительно, как и выше
        uint64_t at_phent = 56; uint64_t at_phnum = 7; uint64_t at_entry = elf_entry;
        uint64_t vec[] = {
            2, a0, a1, 0, // argc=2, argv[0], argv[1], NULL
            0,            // envp NULL
            AT_PHDR, at_phdr,
            AT_PHENT, at_phent,
            AT_PHNUM, at_phnum,
            AT_ENTRY, at_entry,
            AT_PAGESZ, 4096,
            AT_RANDOM, at_random_ptr,
            AT_NULL, 0
        };
        sp -= sizeof(vec); memcpy((void*)sp, vec, sizeof(vec));
        // TLS страница (как раньше)
        uint64_t tls_va = (ustack_top & ~0xFFFFFULL) - 0x1000ULL;
        void* tls_page = kmalloc(0x2000);
        if (tls_page) {
            uint64_t tls_phys = ((uint64_t)tls_page + 0xFFFULL) & ~0xFFFULL;
            paging_map_page(tls_va, tls_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
            memset((void*)tls_va, 0, 0x1000);
        }
        thread_register_user(elf_entry, sp, "init");
        PrintfQEMU("[enter_user] rip=0x%llx rsp=0x%llx cs=0x%x ss=0x%x\n",
                   (unsigned long long)elf_entry,
                   (unsigned long long)sp,
                   (unsigned)USER_CS,
                   (unsigned)USER_DS);
        asm volatile(
            "xor %%rbx, %%rbx; xor %%rdi, %%rdi; xor %%rsi, %%rsi; xor %%rdx, %%rdx;\n"
            "xor %%r12, %%r12; xor %%r13, %%r13; xor %%r14, %%r14; xor %%r15, %%r15;\n"
            :::"rbx","rdi","rsi","rdx","r12","r13","r14","r15");
        asm volatile("sti");
        enter_user_mode(elf_entry, sp);
    }

    

    for(;;) { asm volatile("hlt"); }
} 