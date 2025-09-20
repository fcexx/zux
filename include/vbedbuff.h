#ifndef VBEDBUFF_H
#define VBEDBUFF_H

#include <stdint.h>

// Double buffering functions
void vbedbuff_init();
void vbedbuff_pixel(int x, int y, uint32_t color);
void vbedbuff_clear(uint32_t color);
void vbedbuff_fill_rect(int x, int y, int width, int height, uint32_t color);
void vbedbuff_line(int x1, int y1, int x2, int y2, uint32_t color);
void vbedbuff_circle(int center_x, int center_y, int radius, uint32_t color);
void vbedbuff_draw_char(char c, int x, int y, uint32_t fg_color, uint32_t bg_color);
void vbedbuff_scroll_up_pixels(int pixels, uint32_t bg_color);

// Buffer management
void vbedbuff_flip();
void vbedbuff_swap();
void vbedbuff_clear_back_buffer(uint32_t color);

// Utility functions
bool vbedbuff_is_initialized();
uint32_t* vbedbuff_get_back_buffer();

#endif // VBEDBUFF_H 