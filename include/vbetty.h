#ifndef VBETTY_H
#define VBETTY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void vbetty_init();
void vbetty_set_fg_color(uint32_t color);
void vbetty_set_bg_color(uint32_t color);
void vbetty_clear();
void vbetty_put_char(char c);
void vbetty_print(const char* str);

// Cursor functions
void vbetty_update_cursor();
void vbetty_show_cursor();
void vbetty_hide_cursor();
void vbetty_force_draw_cursor();
void vbetty_force_hide_cursor();

// kprintf function with format support and color escape sequences
int kprintf(const char* format, ...);

uint32_t vbetty_get_cursor_x();
uint32_t vbetty_get_cursor_y();
void vbetty_set_cursor_pos(uint32_t x, uint32_t y);

#ifdef __cplusplus
}
#endif

#endif // VBETTY_H 