#include <stdint.h>

void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a" (value), "Nd" (port));
}

void PrintQEMU(const char* str) {
    while (*str) {
        outb(0xe9, *str);
        str++;
    }
}

// The C++ entry point for the kernel.
extern "C" void kernel_main(void* multiboot2_info, uint32_t multiboot2_magic) {
    // Check multiboot2 magic number
    if (multiboot2_magic != 0x36d76289) {
        PrintQEMU("Invalid multiboot2 magic");
        // Invalid multiboot2 magic
        while (true) {
            __asm__ volatile("hlt");
        }
    }
    else {
        PrintQEMU("Multiboot2 magic is valid");
    }

    while (true) {
        __asm__ volatile("hlt");
    }
} 