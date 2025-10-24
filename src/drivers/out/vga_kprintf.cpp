#include <vbetty.h>
#include <vga.h>
#include <vbe.h>
#include <spinlock.h>
#include <stdarg.h>
#include <stdint.h>
#include <fs_interface.h>

// Console state for VGA text mode
static uint32_t cons_w = 80;
static uint32_t cons_h = 25;
static uint32_t cur_x = 0;
static uint32_t cur_y = 0;

// Current colors (VGA palette indices 0..15)
static uint8_t fg_idx = 7;
static uint8_t bg_idx = 0;
static bool ansi_bold = false;

spinlock_t vga_printf_lock = {0};

static inline void vga_newline() {
        cur_x = 0;
    if (++cur_y >= cons_h) {
        if (vbe_console_ready()) vbec_scroll_up(bg_idx); else vga_scroll_up(bg_idx);
                cur_y = cons_h - 1;
        }
    if (vbe_console_ready()) vbec_set_cursor(cur_x, cur_y); else vga_set_cursor(cur_x, cur_y);
}

// buffered VFS line append to avoid per-char reallocs
static char klog_linebuf[1024];
static size_t klog_linepos = 0;
static inline void klog_linebuf_push(char c){
        if (klog_linepos < sizeof(klog_linebuf)-1) { klog_linebuf[klog_linepos++] = c; }
        if (c == '\n' || klog_linepos >= sizeof(klog_linebuf)-2) {
                klog_linebuf[klog_linepos] = '\0';
                vfs_klog_append(klog_linebuf, (unsigned long)klog_linepos);
                klog_linepos = 0;
        }
}

static inline void vga_putc(char c) {
        if (c == '\n') { vga_newline(); extern void vfs_klog_append(const char*, unsigned long); vfs_klog_append("\n", 1); return; }
    if (c == '\r') { cur_x = 0; if (vbe_console_ready()) vbec_set_cursor(cur_x, cur_y); else vga_set_cursor(cur_x, cur_y); return; }
        if (c == '\b') {
                if (cur_x > 0) { cur_x--; }
                else if (cur_y > 0) { cur_y--; cur_x = cons_w - 1; }
        if (vbe_console_ready()) vbec_put_cell(cur_x, cur_y, ' ', fg_idx, bg_idx); else vga_put_cell(cur_x, cur_y, ' ', fg_idx, bg_idx);
        if (vbe_console_ready()) vbec_set_cursor(cur_x, cur_y); else vga_set_cursor(cur_x, cur_y);
                return;
        }
    if (cur_x >= cons_w) { vga_newline(); }
    if (vbe_console_ready()) vbec_put_cell(cur_x, cur_y, c, fg_idx, bg_idx); else vga_put_cell(cur_x, cur_y, c, fg_idx, bg_idx);
    if (++cur_x >= cons_w) vga_newline(); else { if (vbe_console_ready()) vbec_set_cursor(cur_x, cur_y); else vga_set_cursor(cur_x, cur_y); }
    // append to VFS kernel log (buffered until newline)
    klog_linebuf_push(c);
}

static void vga_puts(const char* s) {
        while (*s) vga_putc(*s++);
}

static void print_number_signed(long long val) {
        if (val == 0) { vga_putc('0'); return; }
        bool neg = val < 0; unsigned long long u = neg ? (unsigned long long)(-val) : (unsigned long long)val;
        char buf[32]; int i = 0;
        while (u) { buf[i++] = (char)('0' + (u % 10ULL)); u /= 10ULL; }
        if (neg) vga_putc('-');
        while (i) vga_putc(buf[--i]);
}

static void print_number_unsigned(unsigned long long u, int base, int width, bool zpad, bool upper) {
        const char* digs = upper ? "0123456789ABCDEF" : "0123456789abcdef";
        char buf[64]; int i = 0;
        if (u == 0) buf[i++] = '0';
        else while (u) { buf[i++] = digs[u % (unsigned)base]; u /= (unsigned)base; }
        int len = i;
        while (width > len) { vga_putc(zpad ? '0' : ' '); width--; }
        while (i) vga_putc(buf[--i]);
}

static inline uint8_t ansi_base_to_vga_idx(int base, bool bright) {
        static const uint8_t normal_map[8] = {0,4,2,6,1,5,3,7};
        static const uint8_t bright_map[8] = {8,12,10,14,9,13,11,15};
        if (base < 0) base = 0;
        if (base > 7) base = 7;
        return bright ? bright_map[base] : normal_map[base];
}

static void ansi_apply_sgr(int code) {
        switch (code) {
                case 0: fg_idx = 15; bg_idx = 0; ansi_bold = false; return;
                case 1: ansi_bold = true; return;
                case 22: ansi_bold = false; return;
                case 39: fg_idx = 15; return;
                case 49: bg_idx = 0; return;
                default: break;
        }
        if (code >= 30 && code <= 37) { fg_idx = ansi_base_to_vga_idx(code - 30, ansi_bold); return; }
        if (code >= 90 && code <= 97) { fg_idx = ansi_base_to_vga_idx(code - 90, true); return; }
        if (code >= 40 && code <= 47) { bg_idx = ansi_base_to_vga_idx(code - 40, false); return; }
        if (code >= 100 && code <= 107){ bg_idx = ansi_base_to_vga_idx(code - 100, true); return; }
}

static const char* ansi_parse_after_bracket(const char* p) {
        int cur = 0; bool have = false;
        while (*p) {
                char ch = *p++;
                if (ch >= '0' && ch <= '9') { cur = cur * 10 + (ch - '0'); have = true; continue; }
                if (ch == ';') { ansi_apply_sgr(have ? cur : 0); cur = 0; have = false; continue; }
                if (ch == 'm') { ansi_apply_sgr(have ? cur : 0); break; }
                break;
        }
        return p;
}

static inline int hex_nibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
}

int kprintf(const char* fmt, ...) {
        acquire(&vga_printf_lock);
        

        // lazy init
    if (vbe_console_ready()) {
        cons_w = vbec_get_width();
        cons_h = vbec_get_height();
        vbec_get_cursor(&cur_x, &cur_y);
    } else {
                cons_w = vga_get_width();
                cons_h = vga_get_height();
                vga_get_cursor(&cur_x, &cur_y);
        }

        va_list ap; va_start(ap, fmt);
        while (*fmt) {
                if (*fmt == '\x1b' && *(fmt+1) == '[') { fmt += 2; fmt = ansi_parse_after_bracket(fmt); continue; }
                if (*fmt == '<' && *(fmt+1) == '(') {
                        // legacy <(bg_fg)>
                        int b = -1, f = -1; fmt += 2; if (*fmt) { b = hex_nibble(*fmt++); }
                        if (*fmt && *fmt != ')') { f = hex_nibble(*fmt++); }
                        while (*fmt && *fmt != ')') fmt++;
                        if (*fmt == ')') fmt++;
                        if (*fmt == '>') fmt++;
                        if (b >= 0) bg_idx = (uint8_t)b;
                        if (f >= 0) fg_idx = (uint8_t)f;
                        continue;
                }
                if (*fmt != '%') { vga_putc(*fmt++); continue; }
                fmt++;
                // flags/width
                bool zpad = false; int width = 0;
                if (*fmt == '0') { zpad = true; fmt++; }
                while (*fmt >= '0' && *fmt <= '9') { width = width*10 + (*fmt - '0'); fmt++; }
                // length
                int lcount = 0; while (*fmt == 'l') { lcount++; fmt++; }
                char spec = *fmt ? *fmt++ : 0;
                switch (spec) {
                        case 'd': case 'i': {
                                if (lcount >= 2) { long long v = va_arg(ap, long long); print_number_signed(v); }
                                else if (lcount == 1) { long v = va_arg(ap, long); print_number_signed((long long)v); }
                                else { int v = va_arg(ap, int); print_number_signed((long long)v); }
                                break;
                        }
                        case 'u': {
                                if (lcount >= 2) { unsigned long long v = va_arg(ap, unsigned long long); print_number_unsigned(v,10,width,zpad,false); }
                                else if (lcount == 1) { unsigned long v = va_arg(ap, unsigned long); print_number_unsigned((unsigned long long)v,10,width,zpad,false); }
                                else { unsigned int v = va_arg(ap, unsigned int); print_number_unsigned((unsigned long long)v,10,width,zpad,false); }
                                break;
                        }
                        case 'x': case 'X': {
                                bool upper = (spec == 'X');
                                if (lcount >= 2) { unsigned long long v = va_arg(ap, unsigned long long); print_number_unsigned(v,16,width,zpad,upper); }
                                else if (lcount == 1) { unsigned long v = va_arg(ap, unsigned long); print_number_unsigned((unsigned long long)v,16,width,zpad,upper); }
                                else { unsigned int v = va_arg(ap, unsigned int); print_number_unsigned((unsigned long long)v,16,width,zpad,upper); }
                                break;
                        }
                        case 'o': {
                                if (lcount >= 2) { unsigned long long v = va_arg(ap, unsigned long long); print_number_unsigned(v,8,width,zpad,false); }
                                else if (lcount == 1) { unsigned long v = va_arg(ap, unsigned long); print_number_unsigned((unsigned long long)v,8,width,zpad,false); }
                                else { unsigned int v = va_arg(ap, unsigned int); print_number_unsigned((unsigned long long)v,8,width,zpad,false); }
                                break;
                        }
                        case 'c': {
                                char ch = (char)va_arg(ap, int); vga_putc(ch); break;
                        }
                        case 's': {
                                const char* s = va_arg(ap, const char*); if (s) vga_puts(s); break;
                        }
                        case 'p': {
                                unsigned long long v = (unsigned long long)va_arg(ap, void*);
                                vga_puts("0x"); print_number_unsigned(v, 16, 0, false, false); break;
                        }
                        case '%': { vga_putc('%'); break; }
                        default: { vga_putc('%'); if (spec) vga_putc(spec); break; }
                }
        }
        va_end(ap);
        // Обновление кадра выполняется только из PIT-таймера
        release(&vga_printf_lock);
        return 0;
}


