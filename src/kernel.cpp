#include "mbparcer.h"
#include "debug.h"
#include "idt.h"
#include "pic.h"
#include "paging.h"

typedef unsigned int uint32_t;

static uint32_t* framebuffer_addr = nullptr;
static uint32_t fb_width = 0;
static uint32_t fb_height = 0;
static uint32_t fb_pitch = 0;
static uint32_t fb_bpp = 0;
static bool framebuffer_initialized = false;

void init_framebuffer(uint64_t addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
void Pixel(int x, int y, uint32_t color);

void parse_multiboot2(uint64_t addr) {
    struct multiboot2_tag* tag;
    
    // Пропускаем первые 8 байт (размер структуры)
    for (tag = (struct multiboot2_tag*)(addr + 8);
         tag->type != 0;
         tag = (struct multiboot2_tag*)((uint8_t*)tag + ((tag->size + 7) & ~7))) {
        
        switch (tag->type) {
            case 8: { // Framebuffer
                struct multiboot2_tag_framebuffer* fb_tag = 
                    (struct multiboot2_tag_framebuffer*)tag;
                
                framebuffer_addr = (uint32_t*)fb_tag->framebuffer_addr;
                fb_width = fb_tag->framebuffer_width;
                fb_height = fb_tag->framebuffer_height;
                fb_pitch = fb_tag->framebuffer_pitch;
                fb_bpp = fb_tag->framebuffer_bpp;
                framebuffer_initialized = true;
                PrintfQEMU("Multiboot2:\n");
                PrintfQEMU("Width: %d\n", fb_width);
                PrintfQEMU("Height: %d\n", fb_height);
                PrintfQEMU("Pitch: %d\n", fb_pitch);
                PrintfQEMU("BPP: %d\n", fb_bpp);
                PrintfQEMU("Addr: 0x%x\n", framebuffer_addr);
                break;
            }
        }
    }
}

void Pixel(int x, int y, uint32_t color) {
    if (!framebuffer_addr) {
        PrintQEMU("!fb");
        return;
    }
    
    if (x < 0 || (uint32_t)x >= fb_width || y < 0 || (uint32_t)y >= fb_height) {
        return;
    }

    uint32_t offset = y * fb_pitch + x * (fb_bpp / 8);
    uint32_t* pixel_addr = (uint32_t*)((uint8_t*)framebuffer_addr + offset);
    *pixel_addr = color;
}

void keyboard_handler(cpu_registers_t* regs) {
    int scancode = inb(0x60);
    PrintfQEMU("Scancode: %x\n", scancode);
    
    // Отправляем EOI для IRQ 1
    pic_send_eoi(1);
}

extern "C" void kernel_main(uint32_t multiboot2_magic, uint64_t multiboot2_info_ptr) {
    PrintfQEMU("Solar OS: Kernel loaded successfully!\n");
    
    parse_multiboot2(multiboot2_info_ptr);
    
    idt_init();
    pic_init();
    pic_unmask_irq(1);  // Размаскировать IRQ 1 (клавиатура)
    pic_mask_irq(0);    // Замаскировать IRQ 0 (системный таймер)
    
    asm volatile("sti");
    
    PrintQEMU("Testing interrupt handling...\n");
    
    PrintQEMU("Testing Pixel function...\n");
    Pixel(10, 10, 0xFFFFFF);
    PrintQEMU("Pixel test completed\n");
    
    // Устанавливаем обработчик page fault
    idt_set_handler(14, [](cpu_registers_t* regs) {
        PrintfQEMU("Page fault at 0x%x, error code: 0x%x\n", regs->rip, regs->error_code);
    });
    
    idt_set_handler(33, keyboard_handler);  // IRQ 1 (клавиатура) = вектор 33
    
    while (1) {
        asm volatile("hlt");
    }
} 
