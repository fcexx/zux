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

typedef unsigned int uint32_t;

extern "C" {
    fs_interface_t* fat32_get_interface(void);
}

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
void keyboard_test_thread() {
    kprintf("\nSolar shell\n");
    
    char input_buffer[128];
    
    while (true) {
        kprintf("> ");
        char* result = kgets(input_buffer, sizeof(input_buffer));
        PrintfQEMU("[shell] input='%s'\n", result ? result : "<null>");
        if (result && strlen(result) > 0) {
            if (strcmp(result, "ls") == 0) {
                PrintQEMU("[shell] cmd ls\n");
                list_directory_contents("/boot");
            }
            else if (strcmp(result, "cat") == 0) {
                PrintQEMU("[shell] cmd cat\n");
                fs_file_t* file = fs_open("/boot/hiiii", FS_OPEN_READ);
                if (file) {
                    char *buffer = (char*)kmalloc(1025);
                    int bytes_read = fs_read(file, buffer, 1024);
                    PrintfQEMU("[shell] cat read -> %d bytes\n", bytes_read);
                    if (bytes_read > 0) {
                        buffer[bytes_read] = '\0';
                        kprintf("%s\n", buffer);
                    } else if (bytes_read == 0) {
                        kprintf("\n");
                    } else {
                        kprintf("Read error\n");
                    }
                    kfree(buffer);
                    fs_close(file);
                } else {
                    PrintQEMU("[shell] cat: open failed\n");
                }
            }
            else if (strcmp(result, "c") == 0) kprintf("<(F0)>Simple command!<(07)>\n"); 
            else if (strcmp(result, "exit") == 0) {
                break;
            }
            else {
                kprintf("Unknown command: %s\n", result);
            }
        }
        
    }
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
    kprintf("Initializing filesystem...\n");
    fs_interface_t* fat32_interface = fat32_get_interface();
    if (fs_init(fat32_interface) == 0) {
        kprintf("Filesystem initialized successfully\n");
    } else {
        kprintf("Failed to initialize filesystem - continuing without filesystem\n");
    }
    list_directory_contents("/");            

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
 
    kprintf("OS is ready; enabling interrupts\n\n");
    asm volatile("sti");

    // ����㧪� ELF �� FAT32 � ����� � userspace
    uint64_t elf_entry = 0, ustack_top = 0;
    PrintfQEMU("Loading /bin/sh...\n");
    if (elf64_load_process("/bin/busybox", 1 << 20, &elf_entry, &ustack_top) == 0) {
        PrintfQEMU("[elf] loaded: entry=0x%llx, ustack=0x%llx\n", (unsigned long long)elf_entry, (unsigned long long)ustack_top);
        // Построить стек: argc=1, argv[0]="/bin/sh", envp=NULL, auxv {PHDR,PHENT,PHNUM,ENTRY,PAGESZ,RANDOM,NULL}
        uint64_t sp = ustack_top;
        const char path_sh[] = "/bin/busybox";
        const uint64_t path_len = sizeof(path_sh); // с NUL
        sp -= path_len;
        memcpy((void*)sp, path_sh, path_len);
        uint64_t arg0 = sp;
        // Сгенерировать 16 байт для AT_RANDOM
        uint8_t rnd[16];
        uint64_t t = pit_ticks ? pit_ticks : 1234567;
        for (int i=0;i<16;i++){
            uint64_t mix = (t >> ((i * 5) % 32)) ^ (uint64_t)(0x9eU + (unsigned)(3 * i));
            rnd[i] = (uint8_t)mix;
        }
        sp -= sizeof(rnd);
        memcpy((void*)sp, rnd, sizeof(rnd));
        uint64_t at_random_ptr = sp;
        // Выравнивание стека на 16
        sp &= ~0xFULL;
        // Константы auxv
        const uint64_t AT_NULL=0, AT_PAGESZ=6, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_ENTRY=9, AT_RANDOM=25;
        // Значения для auxv
        uint64_t at_phdr = (0x20000000ULL /* load_base */) + 64; // e_phoff=64
        uint64_t at_phent = 56;
        uint64_t at_phnum = 7;
        uint64_t at_entry = elf_entry;
        // Вектор: argc, argv[], NULL, envp NULL, auxv пары...
        uint64_t vec[2 /*argc*/ + 2 /*argv0,NULL*/ + 1 /*env null*/ + 2*6 /*aux pairs*/];
        size_t idx = 0;
        vec[idx++] = 1;        // argc
        vec[idx++] = arg0;     // argv[0]
        vec[idx++] = 0;        // argv NULL
        vec[idx++] = 0;        // envp NULL
        // auxv
        vec[idx++] = AT_PHDR;   vec[idx++] = at_phdr;
        vec[idx++] = AT_PHENT;  vec[idx++] = at_phent;
        vec[idx++] = AT_PHNUM;  vec[idx++] = at_phnum;
        vec[idx++] = AT_ENTRY;  vec[idx++] = at_entry;
        vec[idx++] = AT_PAGESZ; vec[idx++] = 4096;
        vec[idx++] = AT_RANDOM; vec[idx++] = at_random_ptr;
        vec[idx++] = AT_NULL;   vec[idx++] = 0;
        sp -= idx * 8ULL;
        memcpy((void*)sp, vec, idx*8ULL);
         // Зарезервируем TLS‑страницу рядом со стеком (FS будет установлен через arch_prctl)
         uint64_t tls_va = (ustack_top & ~0xFFFFFULL) - 0x1000ULL; // страница ниже ближайшей 1Мб границы
         void* tls_page = kmalloc(0x2000);
         if (tls_page) {
             uint64_t tls_phys = ((uint64_t)tls_page + 0xFFFULL) & ~0xFFFULL;
             paging_map_page(tls_va, tls_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
             memset((void*)tls_va, 0, 0x1000);
         }
         // Регистрируем пользовательский процесс и входим
         thread_register_user(elf_entry, sp, "busybox");
        PrintfQEMU("[enter_user] rip=0x%llx rsp=0x%llx cs=0x%x ss=0x%x\n",
                   (unsigned long long)elf_entry,
                   (unsigned long long)sp,
                   (unsigned)USER_CS,
                   (unsigned)USER_DS);
        asm volatile(
            "xor %%rbx, %%rbx; xor %%rdi, %%rdi; xor %%rsi, %%rsi; xor %%rdx, %%rdx;\n"
            "xor %%r12, %%r12; xor %%r13, %%r13; xor %%r14, %%r14; xor %%r15, %%r15;\n"
            :::"rbx","rdi","rsi","rdx","r12","r13","r14","r15");
        enter_user_mode(elf_entry, sp);
    } else {
        kprintf("ELF load failed\n");
    }

    for(;;) { asm volatile("hlt"); }
} 