#ifndef VGA_H
#define VGA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void vga_init();
void vga_clear(uint8_t fg, uint8_t bg);
void vga_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg);
void vga_scroll_up(uint8_t bg);
void vga_set_cursor(uint32_t x, uint32_t y);
void vga_enable_cursor(int enable);
uint32_t vga_get_width();   // 80
uint32_t vga_get_height();  // 25
void vga_get_cursor(uint32_t* x, uint32_t* y);
int kprintf(const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // VGA_H


