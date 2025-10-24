#include <vbe.h>
#include <debug.h>
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
// Track previously drawn cursor to restore underlying pixels from backbuffer
static bool g_prev_cursor_drawn = false;
static uint32_t g_prev_cursor_x = 0, g_prev_cursor_y = 0;
static uint32_t g_palette[16]; // 16-color palette (ARGB)
static bool g_fb_dirty = false; // mark when backbuffer changed
// Dirty rectangle to minimize copies on swap
static uint32_t g_dirty_x0 = 0, g_dirty_y0 = 0, g_dirty_x1 = 0, g_dirty_y1 = 0;
static bool g_cursor_visible = true; // blinking state
static uint32_t g_cursor_phase = 0; // ticks accumulator
static uint32_t g_cursor_period_ms = 50; // blink each 500ms like VGA
// Logical scroll offset in pixel rows (0..g_fb_height-1)
static uint32_t g_scroll_px_off = 0;
static int g_present_enabled = 1;
// Неблокирующий (неатомарный) спин‑флаг для критических секций VBE
static volatile int g_vbe_in_cs = 0;

static inline uint64_t vbe_irq_save_disable(){
        uint64_t flags; asm volatile("pushfq; pop %0; cli" : "=r"(flags) :: "memory"); return flags;
}
static inline void vbe_irq_restore(uint64_t flags){
        asm volatile("push %0; popfq" :: "r"(flags) : "memory", "cc");
}
static inline uint64_t vbe_enter_cs(){ uint64_t f = vbe_irq_save_disable(); g_vbe_in_cs = 1; return f; }
static inline void vbe_leave_cs(uint64_t f){ g_vbe_in_cs = 0; vbe_irq_restore(f); }

// kmalloc/kfree from heap.h

void vbe_init(uint64_t addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
    g_fb_addr = (uint32_t*)(uint64_t)addr;
    g_fb_width = width;
    g_fb_height = height;
    g_fb_pitch = pitch;
    g_fb_bpp = bpp;
        // Если это VGA текстовый режим (80x25 и подобные) — отключаем VBE-консоль
        // Признаки: bpp==16, pitch==width*2, ширина/высота небольшие (ячейки символов), адрес в окрестности 0xB8000
        bool looks_like_vga_text = (bpp == 16) && (pitch == width * 2) && (width <= 200) && (height <= 100) && ((addr & ~0xFFFFULL) == 0x000A0000ULL || addr == 0xB8000ULL);
        if (looks_like_vga_text) {
                g_fb_initialized = false;
                g_frontbuffer = nullptr;
                // backbuffer может остаться невыделенным; консоль VGA возьмёт управление выводом
                PrintfQEMU("[vbe] disabled: VGA text mode detected (addr=0x%llx %ux%u pitch=%u bpp=%u)\n",
                           (unsigned long long)addr, (unsigned)width, (unsigned)height, (unsigned)pitch, (unsigned)bpp);
                return;
        }
        // Разрешим 16/24/32 bpp. Для 16 bpp используем RGB565 при выводе
        g_fb_initialized = (g_fb_addr != nullptr) && width && height && pitch && (bpp == 32 || bpp == 24 || bpp == 16);
    g_frontbuffer = g_fb_addr;
}

bool vbe_is_initialized() {
    return g_fb_initialized;
}

bool vbe_console_ready() {
        return g_fb_initialized && (g_backbuffer != nullptr) && (g_frontbuffer != nullptr);
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
        // map logical y to physical row with scroll offset
        uint32_t y_phys = (uint32_t)((y + g_scroll_px_off) % g_fb_height);
    uint8_t* base = (uint8_t*)g_backbuffer; // draw to backbuffer
        *(uint32_t*)(base + (size_t)y_phys * (size_t)g_fb_width * 4 + (size_t)x * 4) = color;
        // mark dirty rect
        if (!g_fb_dirty) { g_dirty_x0 = (uint32_t)x; g_dirty_y0 = (uint32_t)y; g_dirty_x1 = (uint32_t)x+1; g_dirty_y1 = (uint32_t)y+1; }
        else { if ((uint32_t)x < g_dirty_x0) g_dirty_x0 = (uint32_t)x; if ((uint32_t)y < g_dirty_y0) g_dirty_y0 = (uint32_t)y; if ((uint32_t)x+1 > g_dirty_x1) g_dirty_x1 = (uint32_t)x+1; if ((uint32_t)y+1 > g_dirty_y1) g_dirty_y1 = (uint32_t)y+1; }
	g_fb_dirty = true;
}

void vbe_clear(uint32_t color) {
    if (!g_fb_initialized || !g_backbuffer) return;
        uint64_t irqf = vbe_enter_cs();
        g_scroll_px_off = 0;
    size_t count = (size_t)g_fb_width * (size_t)g_fb_height;
	for (size_t i = 0; i < count; ++i) g_backbuffer[i] = color;
	// full screen dirty
	g_fb_dirty = true; g_dirty_x0 = 0; g_dirty_y0 = 0; g_dirty_x1 = g_fb_width; g_dirty_y1 = g_fb_height;
        vbe_leave_cs(irqf);
}

void vbe_shutdown() {
    // nothing for now (backbuffer leak acceptable until kfree available here)
}

void vbe_set_present_enabled(int enable) { g_present_enabled = enable ? 1 : 0; }

void vbe_swap() {
	if (!g_fb_initialized || !g_backbuffer || !g_frontbuffer) return;
        if (!g_fb_dirty || !g_present_enabled) return; // present only if something changed and enabled
        if (g_vbe_in_cs) return; // пропускаем кадр, если идёт запись в backbuffer
        // clamp dirty rectangle
        uint32_t x0 = (g_dirty_x0 < g_fb_width ? g_dirty_x0 : g_fb_width);
        uint32_t y0 = (g_dirty_y0 < g_fb_height ? g_dirty_y0 : g_fb_height);
        uint32_t x1 = (g_dirty_x1 <= g_fb_width ? g_dirty_x1 : g_fb_width);
        uint32_t y1 = (g_dirty_y1 <= g_fb_height ? g_dirty_y1 : g_fb_height);
        if (x1 <= x0 || y1 <= y0) { g_fb_dirty = false; return; }
    // copy backbuffer to frontbuffer respecting pitch
    uint8_t* src = (uint8_t*)g_backbuffer;
    uint8_t* dst = (uint8_t*)g_frontbuffer;
        size_t row_bytes_full = (size_t)g_fb_width * 4;
        uint32_t copy_w = x1 - x0;
    if (g_fb_bpp == 32) {
                size_t copy_bytes = (size_t)copy_w * 4;
                for (uint32_t y = y0; y < y1; ++y) {
                        uint32_t y_src = (uint32_t)((y + g_scroll_px_off) % g_fb_height);
                        uint8_t* drow = dst + (size_t)y * (size_t)g_fb_pitch + (size_t)x0 * 4;
                        uint8_t* srow = src + (size_t)y_src * row_bytes_full + (size_t)x0 * 4;
                        // copy changed span
            uint32_t* d32 = (uint32_t*)drow;
            uint32_t* s32 = (uint32_t*)srow;
                        for (uint32_t x = 0; x < copy_w; ++x) d32[x] = s32[x];
                }
        } else if (g_fb_bpp == 24) { // 24 bpp
                for (uint32_t y = y0; y < y1; ++y) {
                        uint32_t y_src = (uint32_t)((y + g_scroll_px_off) % g_fb_height);
                        uint8_t* drow = dst + (size_t)y * (size_t)g_fb_pitch + (size_t)x0 * 3;
                        uint32_t* s32 = (uint32_t*)(src + (size_t)y_src * row_bytes_full + (size_t)x0 * 4);
                        for (uint32_t x = 0; x < copy_w; ++x) {
                uint32_t px = s32[x];
                drow[x*3+0] = (uint8_t)(px & 0xFF);
                drow[x*3+1] = (uint8_t)((px >> 8) & 0xFF);
                drow[x*3+2] = (uint8_t)((px >> 16) & 0xFF);
            }
        }
        } else if (g_fb_bpp == 16) { // RGB565
                for (uint32_t y = y0; y < y1; ++y) {
                        uint32_t y_src = (uint32_t)((y + g_scroll_px_off) % g_fb_height);
                        uint16_t* d16 = (uint16_t*)(dst + (size_t)y * (size_t)g_fb_pitch) + x0;
                        uint32_t* s32 = (uint32_t*)(src + (size_t)y_src * row_bytes_full + (size_t)x0 * 4);
                        for (uint32_t x = 0; x < copy_w; ++x) {
                                uint32_t c = s32[x];
                                // ARGB8888 -> RGB565
                                uint16_t r = (uint16_t)((c >> 19) & 0x1F); // 8->5
                                uint16_t g = (uint16_t)((c >> 10) & 0x3F); // 8->6
                                uint16_t b = (uint16_t)((c >> 3)  & 0x1F); // 8->5
                                d16[x] = (uint16_t)((r << 11) | (g << 5) | b);
                        }
                }
        }

        // First, restore previous cursor span from backbuffer if it was drawn and not yet overwritten
        if (g_prev_cursor_drawn) {
                uint32_t px = g_prev_cursor_x;
                uint32_t py = g_prev_cursor_y;
                uint32_t cons_w = vbec_get_width();
                uint32_t cons_h = vbec_get_height();
                if (px < cons_w && py < cons_h) {
                        uint32_t x0p = px * g_cell_w;
                        uint32_t y0p = py * g_cell_h + (g_cell_h - 2);
                        if (y0p >= g_fb_height) y0p = g_fb_height - 1;
                        uint32_t bar_h = 1;
                        uint32_t copy_w = g_cell_w;
                        if (x0p + copy_w > g_fb_width) copy_w = g_fb_width - x0p;
                        for (uint32_t yy = 0; yy < bar_h; ++yy) {
                                uint32_t y_src = (uint32_t)((y0p + yy + g_scroll_px_off) % g_fb_height);
                                uint8_t* drow = ((uint8_t*)g_frontbuffer) + (size_t)(y0p + yy) * (size_t)g_fb_pitch + (size_t)x0p * (g_fb_bpp == 24 ? 3 : (g_fb_bpp == 16 ? 2 : 4));
                                if (g_fb_bpp == 32) {
                                        uint32_t* s32 = g_backbuffer + (size_t)y_src * (size_t)g_fb_width + x0p;
                                        uint32_t* d32 = (uint32_t*)drow;
                                        for (uint32_t xx = 0; xx < copy_w; ++xx) d32[xx] = s32[xx];
                                } else if (g_fb_bpp == 24) {
                                        uint32_t* s32 = g_backbuffer + (size_t)y_src * (size_t)g_fb_width + x0p;
                                        for (uint32_t xx = 0; xx < copy_w; ++xx) {
                                                uint32_t pxv = s32[xx];
                                                drow[xx*3+0] = (uint8_t)(pxv & 0xFF);
                                                drow[xx*3+1] = (uint8_t)((pxv >> 8) & 0xFF);
                                                drow[xx*3+2] = (uint8_t)((pxv >> 16) & 0xFF);
                                        }
                                } else { // 16 bpp RGB565
                                        uint32_t* s32 = g_backbuffer + (size_t)y_src * (size_t)g_fb_width + x0p;
                                        uint16_t* d16 = (uint16_t*)drow;
                                        for (uint32_t xx = 0; xx < copy_w; ++xx) {
                                                uint32_t c = s32[xx];
                                                uint16_t r = (uint16_t)((c >> 19) & 0x1F);
                                                uint16_t g = (uint16_t)((c >> 10) & 0x3F);
                                                uint16_t b = (uint16_t)((c >> 3)  & 0x1F);
                                                d16[xx] = (uint16_t)((r << 11) | (g << 5) | b);
                                        }
                                }
                        }
                }
                g_prev_cursor_drawn = false;
        }

        // Overlay blinking cursor directly on frontbuffer so it stays visible under heavy output
        if (g_cursor_visible) {
                uint32_t cx = g_cursor_x;
                uint32_t cy = g_cursor_y;
        uint32_t cons_w = vbec_get_width();
        uint32_t cons_h = vbec_get_height();
                if (cx < cons_w && cy < cons_h) {
                        uint32_t x0c = cx * g_cell_w;
                        // Destination Y on frontbuffer is logical cell position (copy already applied scroll)
                        uint32_t y0c = cy * g_cell_h + (g_cell_h - 2);
            if (y0c >= g_fb_height) y0c = g_fb_height - 1;
            // 1-пиксельная полоса для гарантии отсутствия выхода за пределы
            uint32_t bar_h = 1;
                        for (uint32_t yy = 0; yy < bar_h; ++yy) {
                                size_t ofs = (size_t)(y0c + yy) * (size_t)g_fb_pitch + (size_t)x0c * (g_fb_bpp == 24 ? 3 : (g_fb_bpp == 16 ? 2 : 4));
                                uint8_t* drow = dst + ofs;
                                if (g_fb_bpp == 32) {
                                        uint32_t* d32 = (uint32_t*)drow;
                                        for (uint32_t xx = 0; xx < g_cell_w; ++xx) d32[xx] ^= 0x00FFFFFFu;
                                } else if (g_fb_bpp == 24) {
                                        for (uint32_t xx = 0; xx < g_cell_w; ++xx) {
                                                drow[xx*3+0] ^= 0xFF;
                                                drow[xx*3+1] ^= 0xFF;
                                                drow[xx*3+2] ^= 0xFF;
                                        }
                                } else if (g_fb_bpp == 16) {
                                        uint16_t* d16 = (uint16_t*)drow;
                                        for (uint32_t xx = 0; xx < g_cell_w; ++xx) d16[xx] ^= 0xFFFFu;
                                }
                        }
                        g_prev_cursor_drawn = true;
                        g_prev_cursor_x = cx;
                        g_prev_cursor_y = cy;
                }
        }

        g_fb_dirty = false; g_dirty_x0 = g_dirty_y0 = 0; g_dirty_x1 = g_dirty_y1 = 0;
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
        uint64_t irqf = vbe_enter_cs();
        uint32_t x0 = cx * g_cell_w; uint32_t y0 = cy * g_cell_h;
        const uint16_t* glyph = ibm_vga_9x16[(unsigned char)c];
        for (uint32_t row = 0; row < g_cell_h; ++row) {
                uint16_t bits = glyph[row];
                uint32_t y_phys = (uint32_t)((y0 + row + g_scroll_px_off) % g_fb_height);
                size_t base_index = (size_t)y_phys * (size_t)g_fb_width + (size_t)x0;
                size_t max_index = (size_t)g_fb_width * (size_t)g_fb_height;
                if (base_index >= max_index) break; // safety guard
                uint32_t* dst = g_backbuffer + base_index;
                // guard per-row to avoid writing past end on last row/column
                uint32_t safe_w = g_cell_w;
                if (base_index + safe_w > max_index) safe_w = (uint32_t)(max_index - base_index);
                for (uint32_t col = 0; col < safe_w; ++col) {
                        // Каждый ряд шрифта использует младшие 9 бит: выбираем бит 8..0
                        bool on = (bits & (1u << (g_cell_w - 1 - col))) != 0;
            dst[col] = on ? fg : bg;
        }
    }
        // mark dirty rect for this cell
        if (!g_fb_dirty) { g_dirty_x0 = x0; g_dirty_y0 = y0; g_dirty_x1 = x0 + g_cell_w; g_dirty_y1 = y0 + g_cell_h; }
        else { if (x0 < g_dirty_x0) g_dirty_x0 = x0; if (y0 < g_dirty_y0) g_dirty_y0 = y0; uint32_t ex = x0 + g_cell_w, ey = y0 + g_cell_h; if (ex > g_dirty_x1) g_dirty_x1 = ex; if (ey > g_dirty_y1) g_dirty_y1 = ey; }
	g_fb_dirty = true;
        vbe_leave_cs(irqf);
}

void vbec_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg) {
    if (!g_fb_initialized) return;
    if (x >= g_cons_w || y >= g_cons_h) return;
        vbec_draw_char(x , y, c, vbec_color(fg), vbec_color(bg));
}

void vbec_scroll_up(uint8_t bg_idx) {
    if (!g_fb_initialized || !g_backbuffer) return;
        uint64_t irqf = vbe_enter_cs();
        // Invalidate previously drawn cursor to avoid trails when logical scroll occurs
        g_prev_cursor_drawn = false;
        // logical scroll by one text row without memmove
        const uint32_t row_px = g_cell_h;
        g_scroll_px_off = (uint32_t)((g_scroll_px_off + row_px) % g_fb_height);
        // clear the newly revealed band at bottom of logical screen
    uint32_t color = vbec_color(bg_idx);
        for (uint32_t i = 0; i < row_px; ++i) {
                uint32_t y_phys = (uint32_t)((g_scroll_px_off + g_fb_height - row_px + i) % g_fb_height);
                uint32_t* line = g_backbuffer + (size_t)y_phys * (size_t)g_fb_width;
		for (uint32_t x = 0; x < g_fb_width; ++x) line[x] = color;
	}
        // full screen dirty after scroll
        g_fb_dirty = true; g_dirty_x0 = 0; g_dirty_y0 = 0; g_dirty_x1 = g_fb_width; g_dirty_y1 = g_fb_height;
        vbe_leave_cs(irqf);
}

void vbec_set_cursor(uint32_t x, uint32_t y) { g_cursor_x = x; g_cursor_y = y; }
void vbec_get_cursor(uint32_t* x, uint32_t* y) { if (x) *x = g_cursor_x; if (y) *y = g_cursor_y; }
uint32_t vbec_get_width() { return g_cons_w ? g_cons_w : (g_fb_width / 8); }
uint32_t vbec_get_height() { return g_cons_h ? g_cons_h : (g_fb_height / 16); }

// Blink cursor over backbuffer. Always toggles regardless of userland faults,
// as PIT continues ticking. We invert a small 8x2 bar at the bottom of the cell.
void vbe_cursor_tick() {
        if (!g_fb_initialized || !g_backbuffer) return;
        if (!g_present_enabled) return;
        // Toggle every ~500ms using pit_ticks proxy value updated from caller.
        // We don't read PIT here to keep this file freestanding; caller calls us each PIT tick.
        g_cursor_phase++;
        if (g_cursor_phase < 250) return;
        g_cursor_phase = 0;
        g_cursor_visible = !g_cursor_visible;

        if (g_cursor_x >= vbec_get_width() || g_cursor_y >= vbec_get_height()) return;
        uint32_t x0 = g_cursor_x * g_cell_w;
        // Destination Y on frontbuffer
        uint32_t y0 = g_cursor_y * g_cell_h + (g_cell_h - 2);
        if (y0 >= g_fb_height) return;
        uint32_t bar_h = 1;
        // mark dirty rect for cursor bar (dest coords)
        if (!g_fb_dirty) { g_dirty_x0 = x0; g_dirty_y0 = y0; g_dirty_x1 = x0 + g_cell_w; g_dirty_y1 = y0 + bar_h; }
        else { if (x0 < g_dirty_x0) g_dirty_x0 = x0; if (y0 < g_dirty_y0) g_dirty_y0 = y0; uint32_t ex = x0 + g_cell_w, ey = y0 + bar_h; if (ex > g_dirty_x1) g_dirty_x1 = ex; if (ey > g_dirty_y1) g_dirty_y1 = ey; }
        g_fb_dirty = true;
}


// ----- Utility drawing helpers -----
void vbe_fill_rect(int x, int y, int width, int height, uint32_t color) {
	if (!g_fb_initialized || !g_backbuffer) return;
	if (width <= 0 || height <= 0) return;
	if (x >= (int)g_fb_width || y >= (int)g_fb_height) return;
        uint64_t irqf = vbe_enter_cs();
	int x0 = x < 0 ? 0 : x;
	int y0 = y < 0 ? 0 : y;
	int x1 = x + width; if (x1 > (int)g_fb_width) x1 = (int)g_fb_width;
	int y1 = y + height; if (y1 > (int)g_fb_height) y1 = (int)g_fb_height;
	for (int yy = y0; yy < y1; ++yy) {
		uint32_t y_phys = (uint32_t)((yy + (int)g_scroll_px_off) % (int)g_fb_height);
		uint32_t* dst = g_backbuffer + (size_t)y_phys * (size_t)g_fb_width + x0;
		for (int xx = x0; xx < x1; ++xx) dst[xx - x0] = color;
	}
        if (!g_fb_dirty) { g_dirty_x0 = (uint32_t)x0; g_dirty_y0 = (uint32_t)y0; g_dirty_x1 = (uint32_t)x1; g_dirty_y1 = (uint32_t)y1; }
        else { if ((uint32_t)x0 < g_dirty_x0) g_dirty_x0 = (uint32_t)x0; if ((uint32_t)y0 < g_dirty_y0) g_dirty_y0 = (uint32_t)y0; if ((uint32_t)x1 > g_dirty_x1) g_dirty_x1 = (uint32_t)x1; if ((uint32_t)y1 > g_dirty_y1) g_dirty_y1 = (uint32_t)y1; }
	g_fb_dirty = true;
        vbe_leave_cs(irqf);
}

void vbec_clear() {
	// Clear with black and reset cursor
	vbe_clear(0x00000000U);
	g_cursor_x = 0;
	g_cursor_y = 0;
}

