#ifndef VBE_H
#define VBE_H

#include <stdint.h>

// VBE framebuffer information
extern uint32_t* framebuffer_addr;
extern uint32_t fb_width;
extern uint32_t fb_height;
extern uint32_t fb_pitch;
extern uint32_t fb_bpp;
extern bool framebuffer_initialized;

// Basic VBE functions
void vbe_init(uint64_t addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
void vbe_pixel(int x, int y, uint32_t color);
void vbe_clear(uint32_t color);
void vbe_fill_rect(int x, int y, int width, int height, uint32_t color);
void vbe_line(int x1, int y1, int x2, int y2, uint32_t color);
void vbe_circle(int center_x, int center_y, int radius, uint32_t color);

// Utility functions
bool vbe_is_initialized();
uint32_t vbe_get_width();
uint32_t vbe_get_height();
uint32_t vbe_get_pitch();
uint32_t vbe_get_bpp();

#endif // VBE_H
