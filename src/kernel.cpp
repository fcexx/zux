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

typedef unsigned int uint32_t;

void parse_multiboot2(uint64_t addr) {
    struct multiboot2_tag* tag;
    
    for (tag = (struct multiboot2_tag*)(addr + 8);
         tag->type != 0;
         tag = (struct multiboot2_tag*)((uint8_t*)tag + ((tag->size + 7) & ~7))) {
        
        switch (tag->type) {
            case 8: { // Framebuffer
                struct multiboot2_tag_framebuffer* fb_tag = 
                    (struct multiboot2_tag_framebuffer*)tag;
                
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

void keyboard_handler(cpu_registers_t* regs) {
    uint8_t scancode = inb(0x60);
    kprintf("Scancode: %d\n", scancode);
    pic_send_eoi(1);
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
    
    idt_set_handler(33, keyboard_handler);
    
    vbedbuff_clear(0x000000);
    vbetty_set_bg_color(0x000000);
    vbetty_set_fg_color(0xFFFFFF);
    
    // Simple test to make sure everything works
    kprintf("<(42)>System initialized successfully!<(07)>\n");
    kprintf("Testing cursor");


    // Enable interrupts
    asm volatile("sti");
    
    for (;;);
} 