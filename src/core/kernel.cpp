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

    ata_init();
    iothread_init(); // ���樠�����㥬 I/O �����஢騪

    // ���樠�����㥬 䠩����� ��⥬� ⮫쪮 ��᫥ ATA
    kprintf("Initializing filesystem...\n");
    fs_interface_t* fat32_interface = fat32_get_interface();
    if (fs_init(fat32_interface) == 0) {
        kprintf("Filesystem initialized successfully\n");
    } else {
        kprintf("Failed to initialize filesystem - continuing without filesystem\n");
    }
    list_directory_contents("/");            

    // ���樠������ GDT/TSS
    gdt_init();
    // �뤥�塞 � ����ࠨ���� kernel-�⥪ ��� �������� (current) ��⮪�, ���� �� ���室� �� ring3 �� IRQ �㤥� �㫥��� rsp0
    void* kstack = kmalloc(16384);
    uint64_t kstack_top = (uint64_t)kstack + 16384;
    thread_current()->kernel_stack = kstack_top;
    tss_set_rsp0(kstack_top);

    // ���樠������ ��⥬��� �맮��� (int 0x80)
    syscall_init();

    kprintf("OS is ready; enabling interrupts\n\n");
    asm volatile("sti");

    // ����㧪� ELF �� FAT32 � ����� � userspace
    uint64_t elf_entry = 0, ustack_top = 0;
    if (elf64_load_process("/boot/user.elf", 1 << 20, &elf_entry, &ustack_top) == 0) {
        PrintfQEMU("[elf] loaded: entry=0x%llx, ustack=0x%llx\n", (unsigned long long)elf_entry, (unsigned long long)ustack_top);
        // Регистрируем пользовательский процесс в списке системных потоков
        thread_register_user(elf_entry, ustack_top, "user.elf");
        PrintfQEMU("[enter_user] rip=0x%llx rsp=0x%llx cs=0x%x ss=0x%x\n",
                   (unsigned long long)elf_entry,
                   (unsigned long long)ustack_top,
                   (unsigned)USER_CS,
                   (unsigned)USER_DS);
        enter_user_mode(elf_entry, ustack_top);
    } else {
        kprintf("ELF load failed\n");
    }

    for(;;) { asm volatile("hlt"); }
} 