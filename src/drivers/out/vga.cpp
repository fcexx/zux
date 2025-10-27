#include <vga.h>
#include <debug.h>
#include <cirrus.h>
#include <stdint.h>

// physical VGA text buffer mapped as identity for early boot; kernel maps virtual at 0xC00B8000
static volatile uint16_t* const VGA_MEM = (uint16_t*)0xB8000;

// Global flag to force legacy VGA routing. Default 1 (legacy) during early boot.
int g_vga_force_legacy = 1;

#define VGA_W 80
#define VGA_H 25

void vga_init() {
        vga_enable_cursor(1);
        vga_set_cursor(0, 0);
}

void vga_clear(uint8_t fg, uint8_t bg) {
        uint16_t attr = (uint16_t)((bg << 4) | (fg & 0x0F));
        uint16_t cell = (uint16_t)((attr << 8) | (uint8_t)' ');
        for (uint32_t i = 0; i < VGA_W * VGA_H; i++) VGA_MEM[i] = cell;
}

void vga_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg) {
        if (x >= VGA_W || y >= VGA_H) return;
        // If Cirrus backend is available and legacy is not forced, forward there
        if (!g_vga_force_legacy && cirrus_console_ready()) {
                cirrus_put_cell(x, y, c, fg, bg);
                return;
        }
        uint16_t attr = (uint16_t)((bg << 4) | (fg & 0x0F));
        VGA_MEM[y * VGA_W + x] = (uint16_t)((attr << 8) | (uint8_t)c);
}

void vga_scroll_up(uint8_t bg) {
        // Prefer backend scroll if available
        if (!g_vga_force_legacy && cirrus_console_ready()) { cirrus_scroll_up(bg); return; }
        // Move lines up
        for (uint32_t y = 0; y < VGA_H - 1; y++) {
                for (uint32_t x = 0; x < VGA_W; x++) {
                        VGA_MEM[y * VGA_W + x] = VGA_MEM[(y + 1) * VGA_W + x];
                }
        }
        // Clear last line
        uint16_t attr = (uint16_t)((bg << 4) | 0x0F);
        uint16_t cell = (uint16_t)((attr << 8) | (uint8_t)' ');
        for (uint32_t x = 0; x < VGA_W; x++) VGA_MEM[(VGA_H - 1) * VGA_W + x] = cell;
}

void vga_set_cursor(uint32_t x, uint32_t y) {
        // If Cirrus backend available and not forced to legacy, forward cursor
        if (!g_vga_force_legacy && cirrus_console_ready()) { cirrus_set_cursor(x, y); return; }
        uint16_t pos = (uint16_t)(y * VGA_W + x);
        outb(0x3D4, 0x0F); outb(0x3D5, (uint8_t)(pos & 0xFF));
        outb(0x3D4, 0x0E); outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

void vga_enable_cursor(int enable) {
        outb(0x3D4, 0x0A);
        uint8_t start = inb(0x3D5);
        if (enable) start &= 0xDF; else start |= 0x20; // bit5
        outb(0x3D4, 0x0A); outb(0x3D5, start);
}

uint32_t vga_get_width()  { return VGA_W; }
uint32_t vga_get_height() { return VGA_H; }

void vga_get_cursor(uint32_t* x, uint32_t* y) {
        // Read cursor position from VGA CRT controller
        outb(0x3D4, 0x0F); uint8_t lo = inb(0x3D5);
        outb(0x3D4, 0x0E); uint8_t hi = inb(0x3D5);
        uint16_t pos = (uint16_t)((hi << 8) | lo);
        if (x) *x = (uint32_t)(pos % VGA_W);
        if (y) *y = (uint32_t)(pos / VGA_W);
}