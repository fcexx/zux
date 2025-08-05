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
#include <ps2.h>

typedef unsigned int uint32_t;

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
    kprintf("Test thread started\n");
    while (true) {
        kprintf("Test thread running\n");
        thread_sleep(1000);
    }
}

void keyboard_test_thread() {
    kprintf("Keyboard test thread started\n");
    kprintf("Testing kgets with arrow key support:\n");
    kprintf("Use arrow keys to navigate, Home/End to go to start/end\n");
    kprintf("Delete to remove character under cursor\n");
    
    char input_buffer[256];
    
    while (true) {
        kgets(input_buffer, sizeof(input_buffer));
    }
}

extern "C" void kernel_main(uint32_t multiboot2_magic, uint64_t multiboot2_info_ptr) {
    parse_multiboot2(multiboot2_info_ptr);
    
    idt_init();
    pic_init();
    pit_init();
    pic_unmask_irq(0);
    pic_unmask_irq(1);
    
    heap_init();
    vbedbuff_init();
    vbetty_init();

    // Инициализируем PS/2 клавиатуру
    ps2_keyboard_init();
    
    vbedbuff_clear(0x000000);
    vbetty_set_bg_color(0x000000);
    vbetty_set_fg_color(0xC4C4C4);

    kprintf("VBE 100x75 ready\n");
    kprintf("Testing cursor\n");
    
    thread_init();
    thread_create(keyboard_test_thread, "keyboard_test");
    
    // Enable interrupts
    asm volatile("sti");
    PrintfQEMU("Interrupts enabled\n");
    
    // Основной цикл системы
    while (true) {
        asm volatile("hlt");
    }
} 