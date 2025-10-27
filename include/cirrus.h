#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Minimal Cirrus CL-GD54xx driver API (fallback-friendly)

// Initialize driver and detect device on PCI bus
void cirrus_init(void);

// Returns non-zero if Cirrus console is ready to accept output
int cirrus_console_ready(void);

// Text-like cell put (compat with vga_put_cell)
void cirrus_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg);

void cirrus_set_cursor(uint32_t x, uint32_t y);
void cirrus_get_cursor(uint32_t* x, uint32_t* y);

// Framebuffer control: set physical framebuffer, size and bpp
void cirrus_set_framebuffer(void* fb_phys_addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);

// Pixel operations (write pixel in current framebuffer)
void cirrus_put_pixel(uint32_t x, uint32_t y, uint32_t color);

uint32_t cirrus_get_width(void);
uint32_t cirrus_get_height(void);

void cirrus_scroll_up(uint8_t bg_idx);

// Take over console from legacy VGA text mode: copy current 80x25 text buffer
// into Cirrus framebuffer and mark console as active.
void cirrus_takeover_console(void);

// Write raw bytes to A000 graphics area (offset from framebuffer base)
void cirrus_write_a000(uint32_t offset, const void* src, uint32_t len);

// Emulate a write to text-mode B800 cell (index = y*80 + x)
void cirrus_write_b800_cell(uint32_t index, uint16_t cell);

// Palette operations (256 entries). Values 0..63 for VGA DAC compatibility
void cirrus_set_palette_entry(uint8_t index, uint8_t r, uint8_t g, uint8_t b);
void cirrus_init_default_palette(void);

#ifdef __cplusplus
}
#endif


