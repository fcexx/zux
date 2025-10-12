#include <vbe.h>
#include <heap.h>
#include <fonts/font9x16-ibm-vga.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint32_t* g_fb_addr = nullptr;
static uint32_t g_fb_width = 0;
static uint32_t g_fb_height = 0;
static uint32_t g_fb_pitch = 0;
static uint32_t g_fb_bpp = 0;
static bool g_fb_initialized = false;
static uint32_t* g_backbuffer = nullptr; // double-buffer in system memory
static uint32_t* g_frontbuffer = nullptr; // alias to g_fb_addr
static uint32_t g_cons_w = 0, g_cons_h = 0; // text grid size
static const uint32_t g_cell_w = 9; // 9x16 VGA glyphs
static const uint32_t g_cell_h = 16;
static uint32_t g_cursor_x = 0, g_cursor_y = 0;
static uint32_t g_palette[16]; // 16-color palette (ARGB)
static bool g_fb_dirty = false; // mark when backbuffer changed
static bool g_cursor_visible = true; // blinking state
static uint32_t g_cursor_phase = 0; // ticks accumulator
static uint32_t g_cursor_period_ms = 50; // blink each 500ms like VGA

// kmalloc/kfree from heap.h

void vbe_init(uint64_t addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
    g_fb_addr = (uint32_t*)(uint64_t)addr;
    g_fb_width = width;
    g_fb_height = height;
    g_fb_pitch = pitch;
    g_fb_bpp = bpp;
    // Разрешим 16/24/32 bpp. Для 16 bpp используем RGB565 при выводе
    g_fb_initialized = (g_fb_addr != nullptr) && width && height && pitch && (bpp == 32 || bpp == 24 || bpp == 16);
    g_frontbuffer = g_fb_addr;
}

bool vbe_is_initialized() {
    return g_fb_initialized;
}

uint32_t vbe_get_width() { return g_fb_width; }
uint32_t vbe_get_height() { return g_fb_height; }
uint32_t vbe_get_pitch() { return g_fb_pitch; }
uint32_t vbe_get_bpp() { return g_fb_bpp; }
uint64_t vbe_get_addr() { return (uint64_t)(uint64_t)g_fb_addr; }

// Simple pixel plotter for potential future use
void vbe_pixel(int x, int y, uint32_t color) {
    if (!g_fb_initialized) return;
    if (x < 0 || y < 0) return;
    if ((uint32_t)x >= g_fb_width || (uint32_t)y >= g_fb_height) return;
    uint8_t* base = (uint8_t*)g_backbuffer; // draw to backbuffer
    *(uint32_t*)(base + (size_t)y * (size_t)g_fb_width * 4 + (size_t)x * 4) = color;
	g_fb_dirty = true;
}

void vbe_clear(uint32_t color) {
    if (!g_fb_initialized || !g_backbuffer) return;
    size_t count = (size_t)g_fb_width * (size_t)g_fb_height;
	for (size_t i = 0; i < count; ++i) g_backbuffer[i] = color;
	g_fb_dirty = true;
}

void vbe_shutdown() {
    // nothing for now (backbuffer leak acceptable until kfree available here)
}

void vbe_swap() {
	if (!g_fb_initialized || !g_backbuffer || !g_frontbuffer) return;
	if (!g_fb_dirty) return; // present only if something changed
    // copy backbuffer to frontbuffer respecting pitch
    uint8_t* src = (uint8_t*)g_backbuffer;
    uint8_t* dst = (uint8_t*)g_frontbuffer;
    size_t row_bytes = (size_t)g_fb_width * 4;
    if (g_fb_bpp == 32) {
        for (uint32_t y = 0; y < g_fb_height; ++y) {
            uint8_t* drow = dst + (size_t)y * (size_t)g_fb_pitch;
            uint8_t* srow = src + (size_t)y * row_bytes;
            // fast 32bpp copy by dword
            uint32_t* d32 = (uint32_t*)drow;
            uint32_t* s32 = (uint32_t*)srow;
            for (uint32_t x = 0; x < g_fb_width; ++x) d32[x] = s32[x];
        }
    } else if (g_fb_bpp == 24) { // 24 bpp
        for (uint32_t y = 0; y < g_fb_height; ++y) {
            uint8_t* drow = dst + (size_t)y * (size_t)g_fb_pitch;
            uint32_t* s32 = (uint32_t*)(src + (size_t)y * row_bytes);
            for (uint32_t x = 0; x < g_fb_width; ++x) {
                uint32_t px = s32[x];
                drow[x*3+0] = (uint8_t)(px & 0xFF);
                drow[x*3+1] = (uint8_t)((px >> 8) & 0xFF);
                drow[x*3+2] = (uint8_t)((px >> 16) & 0xFF);
            }
        }
    } else if (g_fb_bpp == 16) { // RGB565
        for (uint32_t y = 0; y < g_fb_height; ++y) {
            uint16_t* d16 = (uint16_t*)(dst + (size_t)y * (size_t)g_fb_pitch);
            uint32_t* s32 = (uint32_t*)(src + (size_t)y * row_bytes);
            for (uint32_t x = 0; x < g_fb_width; ++x) {
                uint32_t c = s32[x];
                // ARGB8888 -> RGB565
                uint16_t r = (uint16_t)((c >> 19) & 0x1F); // 8->5
                uint16_t g = (uint16_t)((c >> 10) & 0x3F); // 8->6
                uint16_t b = (uint16_t)((c >> 3)  & 0x1F); // 8->5
                d16[x] = (uint16_t)((r << 11) | (g << 5) | b);
            }
        }
    }
	g_fb_dirty = false;
}

// ----- VBE Console (text) -----
static inline uint32_t vbec_color(uint8_t idx) { return g_palette[idx & 15]; }

void vbec_init_console() {
    if (!g_fb_initialized) return;
    // allocate backbuffer now that heap is initialized
    if (!g_backbuffer) {
        size_t bytes = (size_t)g_fb_width * (size_t)g_fb_height * 4;
        g_backbuffer = (uint32_t*)kmalloc(bytes);
        if (!g_backbuffer) {
            // Без backbuffer корректно можем работать только при 32 bpp
            if (g_fb_bpp == 32) {
                g_backbuffer = (uint32_t*)g_frontbuffer;
            } else {
                // отключим VBE‑консоль, чтобы не писать 32-битные пиксели в 16/24-битный буфер
                g_fb_initialized = false;
                return;
            }
        }
        if (g_backbuffer && g_backbuffer != (uint32_t*)g_frontbuffer) {
            for (size_t i = 0; i < (bytes / 4); ++i) g_backbuffer[i] = 0x00000000U;
        }
    }
    // 9x16 font grid and palette
    g_cons_w = g_fb_width / g_cell_w;
    g_cons_h = g_fb_height / g_cell_h;
    g_palette[0]=0xFF000000; g_palette[1]=0xFF0000AA; g_palette[2]=0xFF00AA00; g_palette[3]=0xFF00AAAA;
    g_palette[4]=0xFFAA0000; g_palette[5]=0xFFAA00AA; g_palette[6]=0xFFAA5500; g_palette[7]=0xFFAAAAAA;
    g_palette[8]=0xFF555555; g_palette[9]=0xFF5555FF; g_palette[10]=0xFF55FF55; g_palette[11]=0xFF55FFFF;
    g_palette[12]=0xFFFF5555; g_palette[13]=0xFFFF55FF; g_palette[14]=0xFFFFFF55; g_palette[15]=0xFFFFFFFF;
    g_cursor_x = g_cursor_y = 0;
	vbe_clear(0x00000000);
}

void vbec_set_palette_entry(uint8_t idx, uint8_t r, uint8_t g, uint8_t b) {
    g_palette[idx & 15] = 0xFF000000U | ((uint32_t)r) | ((uint32_t)g << 8) | ((uint32_t)b << 16);
}

void vbec_set_fg(uint8_t idx) { (void)idx; }
void vbec_set_bg(uint8_t idx) { (void)idx; }

// glyphs come from included header font9x16-ibm-vga.h (each row uses lower 9 bits)
static void vbec_draw_char(uint32_t cx, uint32_t cy, char c, uint32_t fg, uint32_t bg) {
    uint32_t x0 = cx * g_cell_w; uint32_t y0 = cy * g_cell_h;
    const uint16_t* glyph = ibm_vga_9x16[(unsigned char)c];
    for (uint32_t row = 0; row < g_cell_h; ++row) {
        uint16_t bits = glyph[row];
        uint32_t* dst = g_backbuffer + ((size_t)(y0 + row) * (size_t)g_fb_width) + x0;
        for (uint32_t col = 0; col < g_cell_w; ++col) {
            bool on = (bits & (1u << (g_cell_w - 1 - col))) != 0;
            dst[col] = on ? fg : bg;
        }
    }
	g_fb_dirty = true;
}

void vbec_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg) {
    if (!g_fb_initialized) return;
    if (x >= g_cons_w || y >= g_cons_h) return;
    vbec_draw_char(x, y, c, vbec_color(fg), vbec_color(bg));
}

void vbec_scroll_up(uint8_t bg_idx) {
    if (!g_fb_initialized || !g_backbuffer) return;
    // scroll by 16 pixel rows
    uint32_t row_px = 16;
    size_t row_bytes = (size_t)g_fb_width * 4;
    size_t band_bytes = (size_t)row_px * row_bytes;
    uint8_t* buf = (uint8_t*)g_backbuffer;
    size_t total_bytes = (size_t)g_fb_height * row_bytes;
    size_t visible = total_bytes - band_bytes;
	memmove(buf, buf + band_bytes, visible);
    // clear last band
    uint32_t color = vbec_color(bg_idx);
	for (uint32_t y = g_fb_height - row_px; y < g_fb_height; ++y) {
		uint32_t* line = (uint32_t*)(buf + (size_t)y * row_bytes);
		for (uint32_t x = 0; x < g_fb_width; ++x) line[x] = color;
	}
	g_fb_dirty = true;
}

void vbec_set_cursor(uint32_t x, uint32_t y) { g_cursor_x = x; g_cursor_y = y; }
void vbec_get_cursor(uint32_t* x, uint32_t* y) { if (x) *x = g_cursor_x; if (y) *y = g_cursor_y; }
uint32_t vbec_get_width() { return g_cons_w ? g_cons_w : (g_fb_width / 8); }
uint32_t vbec_get_height() { return g_cons_h ? g_cons_h : (g_fb_height / 16); }

// Blink cursor over backbuffer. Always toggles regardless of userland faults,
// as PIT continues ticking. We invert a small 8x2 bar at the bottom of the cell.
void vbe_cursor_tick() {
    if (!g_fb_initialized || !g_backbuffer) return;
    // Toggle every ~500ms using pit_ticks proxy value updated from caller.
    // We don't read PIT here to keep this file freestanding; caller calls us each PIT tick.
    g_cursor_phase++;
    if (g_cursor_phase < 250) return;
    g_cursor_phase = 0;
    g_cursor_visible = !g_cursor_visible;

    if (g_cursor_x >= vbec_get_width() || g_cursor_y >= vbec_get_height()) return;
    uint32_t x0 = g_cursor_x * g_cell_w;
    uint32_t y0 = g_cursor_y * g_cell_h + (g_cell_h - 2); // 2px bar at bottom
    if (y0 >= g_fb_height) return;
    uint32_t bar_h = (y0 + 2 <= g_fb_height) ? 2 : 1;
    for (uint32_t yy = 0; yy < bar_h; ++yy) {
        uint32_t* row = g_backbuffer + ((size_t)(y0 + yy) * (size_t)g_fb_width) + x0;
        for (uint32_t xx = 0; xx < g_cell_w; ++xx) {
            // XOR invert to match foreground regardless of palette; stable toggle
            row[xx] ^= 0x00FFFFFFu;
        }
    }
    g_fb_dirty = true;
}


// ----- Utility drawing helpers -----
void vbe_fill_rect(int x, int y, int width, int height, uint32_t color) {
	if (!g_fb_initialized || !g_backbuffer) return;
	if (width <= 0 || height <= 0) return;
	if (x >= (int)g_fb_width || y >= (int)g_fb_height) return;
	int x0 = x < 0 ? 0 : x;
	int y0 = y < 0 ? 0 : y;
	int x1 = x + width; if (x1 > (int)g_fb_width) x1 = (int)g_fb_width;
	int y1 = y + height; if (y1 > (int)g_fb_height) y1 = (int)g_fb_height;
	for (int yy = y0; yy < y1; ++yy) {
		uint32_t* dst = g_backbuffer + (size_t)yy * (size_t)g_fb_width + x0;
		for (int xx = x0; xx < x1; ++xx) dst[xx - x0] = color;
	}
	g_fb_dirty = true;
}

void vbec_clear() {
	// Clear with black and reset cursor
	vbe_clear(0x00000000U);
	g_cursor_x = 0;
	g_cursor_y = 0;
}

