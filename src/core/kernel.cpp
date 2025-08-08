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

typedef unsigned int uint32_t;

extern "C" {
    fs_interface_t* fat32_get_interface(void);
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

// Пример функции для чтения содержимого папки
void list_directory_contents(const char* path) {
    
    if (!path) {
        kprintf("Error: null path\n");
        return;
    }
    
    kprintf("Listing directory: %s\n", path);
    
    // Проверяем, инициализирована ли файловая система
    if (!fs_is_initialized()) {
        kprintf("Filesystem not initialized\n");
        return;
    }
    
    // Открываем директорию
    fs_dir_t* dir = fs_opendir(path);
    
    if (!dir) {
        kprintf("Failed to open directory: %s\n", path);
        return;
    }

    kprintf("Directory opened successfully\n");
    
    fs_dirent_t entry;
    int count = 0;
    
    // Читаем все записи в директории с ограничением
    while (count < 10) {
        int result = fs_readdir(dir, &entry);
        
        if (result != 0) {
            // Больше нет записей или произошла ошибка
            break;
        }
        
        count++;
        
        // Проверяем, что имя не пустое
        if (entry.name[0] == '\0') {
            continue;
        }

        // Определяем тип записи
        const char* type = (entry.attributes & FS_ATTR_DIRECTORY) ? "DIR" : "FILE";
        
        // Выводим информацию о файле/папке
        kprintf(" [%s] %s", type, entry.name);
        
        // Если это файл, показываем размер
        if (!(entry.attributes & FS_ATTR_DIRECTORY)) {
            kprintf(" (%u bytes)", (unsigned int)entry.size);
        }
        
        kprintf("\n");
    }
    
    kprintf("total %d\n", count);
    
    // Закрываем директорию
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

static void user_demo() {
    // call write(1, "Hello from user\n", 17) via int 0x80
    const char* msg = "Hello from user\n";
    register uint64_t rax asm("rax") = SYS_WRITE;
    register uint64_t rdi asm("rdi") = 1;
    register uint64_t rsi asm("rsi") = (uint64_t)msg;
    register uint64_t rdx asm("rdx") = 17;
    asm volatile ("int $0x80" : "+a"(rax) : "D"(rdi), "S"(rsi), "d"(rdx) : "rcx", "r11", "memory");
    // exit(0)
    rax = SYS_EXIT; rdi = 0; rsi = 0; rdx = 0;
    asm volatile ("int $0x80" : "+a"(rax) : "D"(rdi), "S"(rsi), "d"(rdx) : "rcx", "r11", "memory");
    for(;;) { asm volatile("hlt"); }
}

extern "C" void kernel_main(uint32_t multiboot2_magic, uint64_t multiboot2_info_ptr) {
    parse_multiboot2(multiboot2_info_ptr);
    
    idt_init();
    pic_init();
    pit_init();
    pic_unmask_irq(0);
    pic_unmask_irq(1);
    pic_unmask_irq(14);
    pic_unmask_irq(15);
    
    // включаем страничную адресацию ранним вызовом
    paging_init();

    // Точный маппинг фреймбуфера (после parse_multiboot2/vbe_init, до любого доступа)
    if (framebuffer_addr && fb_height && fb_pitch) {
        uint64_t fb_start = (uint64_t)framebuffer_addr;
        uint64_t fb_size  = (uint64_t)fb_height * (uint64_t)fb_pitch;
        uint64_t map_start = fb_start & ~0xFULL; // выравнивание вниз к 4К
        uint64_t map_end   = (fb_start + fb_size + 0xFFFULL) & ~0xFULL; // вверх к 4К
        uint64_t map_size  = map_end - map_start;
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
    iothread_init(); // Инициализируем I/O планировщик

    // Инициализируем файловую систему только после ATA
    kprintf("Initializing filesystem...\n");
    fs_interface_t* fat32_interface = fat32_get_interface();
    if (fs_init(fat32_interface) == 0) {
        kprintf("Filesystem initialized successfully\n");
    } else {
        kprintf("Failed to initialize filesystem - continuing without filesystem\n");
    }
    list_directory_contents("/");            
    thread_create(keyboard_test_thread, "basic_shell");

    // Инициализация GDT/TSS
    gdt_init();
    // Выделяем и настраиваем kernel-стек для главного (current) потока, иначе при переходе из ring3 по IRQ будет нулевой rsp0
    void* kstack = kmalloc(16384);
    uint64_t kstack_top = (uint64_t)kstack + 16384;
    thread_current()->kernel_stack = kstack_top;
    tss_set_rsp0(kstack_top);

    // Инициализация системных вызовов (int 0x80)
    syscall_init();

    asm volatile("sti");

    // Подготовка простого перехода в ring3: выделяем стек юзера
    void* ustack = kmalloc(16384);
    uint64_t ustack_top = ((uint64_t)ustack + 16384) & ~0xFULL; // 16-byte align
    // Разрешаем доступ user к страницам стека: диапазон [top-size, top) с округлением до страниц, включая страницу с top-1
    uint64_t usr_stack_start = ((ustack_top - 16384) & ~0xFFFULL);
    uint64_t usr_stack_end   = (ustack_top + 0xFFFULL) & ~0xFFFULL; // включить страницу, где лежит ustack_top
    uint64_t usr_stack_size  = usr_stack_end - usr_stack_start;
    paging_map_range(usr_stack_start, usr_stack_start, usr_stack_size, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    // Разрешаем пользователю выполнить страницу с user_demo (временно)
    uint64_t ucode = ((uint64_t)user_demo) & ~0xFFFULL;
    paging_map_range(ucode, ucode, 0x1000, PAGE_PRESENT | PAGE_USER);
    PrintfQEMU("\nPAGING MAP RANGE 2 OK\n");

    // В реальном случае сюда загрузим ELF, пока ? тестовая функция
    enter_user_mode((uint64_t)user_demo, ustack_top);

    while (true); // kernel idle
} 