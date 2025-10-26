#ifndef VBE_H
#define VBE_H

#include <stdint.h>

// VBE framebuffer information
// Accessors instead of globals

// Basic VBE functions
void vbe_init(uint64_t addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
void vbe_shutdown();
void vbe_swap();
// allow/disallow frame from PIT (protective flag early initialization)
// like a spinlock
void vbe_set_present_enabled(int enable);
void vbe_pixel(int x, int y, uint32_t color);
void vbe_clear(uint32_t color);
void vbe_fill_rect(int x, int y, int width, int height, uint32_t color);

// Utility functions
bool vbe_is_initialized();
// true when text VBE console is ready (has backbuffer)
bool vbe_console_ready();
uint32_t vbe_get_width();
uint32_t vbe_get_height();
uint32_t vbe_get_pitch();
uint32_t vbe_get_bpp();
uint64_t vbe_get_addr();

// VBE console (text) API - 16-color palette over 32-bit framebuffer with double buffering
void vbec_init_console();
void vbec_set_palette_entry(uint8_t idx, uint8_t r, uint8_t g, uint8_t b);
void vbec_set_fg(uint8_t idx);
void vbec_set_bg(uint8_t idx);
void vbec_clear();
void vbec_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg);
void vbec_scroll_up(uint8_t bg_idx);
void vbec_set_cursor(uint32_t x, uint32_t y);
void vbec_get_cursor(uint32_t* x, uint32_t* y);

int vbec_set_font(const void* data, uint32_t data_size, uint8_t width, uint8_t height);

uint32_t vbec_get_width();
uint32_t vbec_get_height();
uint32_t vbe_get_cons_width();
uint32_t vbe_get_cons_height();
// Cursor blinking support for VBE console
void vbe_cursor_tick();

// Emergency: force-unlock VBE console critical section (used from fault handlers)
void vbe_force_unlock();

#endif // VBE_H
