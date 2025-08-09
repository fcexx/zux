#include <vbetty.h>
#include <vbe.h>
#include <vbedbuff.h>
#include <string.h>
#include <fonts/font8x8.h>
#include <debug.h>
#include <stdint.h>
#include <stdarg.h>
#include <heap.h>
#include <spinlock.h>

// Console dimensions
static uint32_t console_width_chars;
static uint32_t console_height_chars;

// Cursor position
static uint32_t vbetty_cursor_x;
static uint32_t vbetty_cursor_y;

// Default colors
static uint32_t current_fg_color = 0xFFFFFF; // White
static uint32_t current_bg_color = 0x000000; // Black

// Cursor state
static bool cursor_visible = false; // Start with cursor invisible
static uint64_t cursor_blink_counter = 0;
static const uint64_t cursor_blink_interval = 5; // 5 ticks at 1000Hz = 5ms (much faster blinking)

// Screen buffer to store characters and their colors
static char* screen_buffer = nullptr;
static uint32_t* fg_color_buffer = nullptr;
static uint32_t* bg_color_buffer = nullptr;

spinlock_t vbelock;

// Initialize VBETTY console
void vbetty_init() {
    if (!vbe_is_initialized()) {
        return;
    }

    if (!vbedbuff_is_initialized()) {
        vbedbuff_init();
        if (!vbedbuff_is_initialized()) {
            return;
        }
    }

    console_width_chars = vbe_get_width() / 8;  // 8 px per char
    console_height_chars = vbe_get_height() / 8; // 8 px per char

    // Проверяем, что размеры разумные
    if (console_width_chars == 0 || console_height_chars == 0) {
        PrintfQEMU("ERROR: Invalid console dimensions: %ux%u\n", console_width_chars, console_height_chars);
        console_width_chars = 80;  // Fallback values
        console_height_chars = 25;
    }
    
    PrintfQEMU("VBETTY: Console dimensions: %ux%u chars\n", console_width_chars, console_height_chars);

    vbetty_cursor_x = 0;
    vbetty_cursor_y = 0;
    
    // Проверяем, что курсор в правильной позиции
    PrintfQEMU("VBETTY: Initial cursor position: (%u,%u)\n", vbetty_cursor_x, vbetty_cursor_y);
    
    // Allocate screen buffers
    size_t buffer_size = console_width_chars * console_height_chars;
    screen_buffer = (char*)kmalloc(buffer_size);
    fg_color_buffer = (uint32_t*)kmalloc(buffer_size * sizeof(uint32_t));
    bg_color_buffer = (uint32_t*)kmalloc(buffer_size * sizeof(uint32_t));
    
    // Initialize buffers
    if (screen_buffer && fg_color_buffer && bg_color_buffer) {
        PrintfQEMU("VBETTY: Initializing buffers with size=%zu\n", buffer_size);
        for (size_t i = 0; i < buffer_size; i++) {
            screen_buffer[i] = ' ';
            fg_color_buffer[i] = current_fg_color;
            bg_color_buffer[i] = current_bg_color;
        }
        PrintfQEMU("VBETTY: Screen buffers initialized successfully\n");
    } else {
        PrintfQEMU("VBETTY: Failed to allocate screen buffers\n");
        PrintfQEMU("VBETTY: screen_buffer=%p, fg_color_buffer=%p, bg_color_buffer=%p\n", 
                   screen_buffer, fg_color_buffer, bg_color_buffer);
    }
    
    // Показываем курсор после инициализации
    vbetty_show_cursor();
    PrintfQEMU("VBETTY: Cursor enabled\n");
}

// Set foreground color
void vbetty_set_fg_color(uint32_t color) {
    current_fg_color = color;
}

// Set background color
void vbetty_set_bg_color(uint32_t color) {
    current_bg_color = color;
}

// Clear the console
void vbetty_clear() {
    vbedbuff_clear(current_bg_color);
    vbetty_cursor_x = 0;
    vbetty_cursor_y = 0;

    if (screen_buffer && fg_color_buffer && bg_color_buffer) {
        size_t buffer_size = console_width_chars * console_height_chars;
        for (size_t i = 0; i < buffer_size; i++) {
            screen_buffer[i] = ' ';
            fg_color_buffer[i] = current_fg_color;
            bg_color_buffer[i] = current_bg_color;
        }
    }
}

// Ultra-fast scroll - only update what changed
static void vbetty_scroll_up() {
    if (!screen_buffer || !fg_color_buffer || !bg_color_buffer) {
        return;
    }
    
    // Shift screen buffer contents up by one line
    size_t line_size = console_width_chars;
    size_t total_lines = console_height_chars;
    
    // Move all lines up by one (copy from line 1 to line 0, line 2 to line 1, etc.)
    for (size_t line = 0; line < total_lines - 1; line++) {
        size_t src_offset = (line + 1) * line_size;
        size_t dst_offset = line * line_size;
        
        // Copy characters
        memcpy(&screen_buffer[dst_offset], &screen_buffer[src_offset], line_size);
        
        // Copy foreground colors
        memcpy(&fg_color_buffer[dst_offset], &fg_color_buffer[src_offset], line_size * sizeof(uint32_t));
        
        // Copy background colors
        memcpy(&bg_color_buffer[dst_offset], &bg_color_buffer[src_offset], line_size * sizeof(uint32_t));
    }
    
    // Clear the last line with spaces and default colors
    size_t last_line_offset = (total_lines - 1) * line_size;
    for (size_t i = 0; i < line_size; i++) {
        screen_buffer[last_line_offset + i] = ' ';
        fg_color_buffer[last_line_offset + i] = current_fg_color;
        bg_color_buffer[last_line_offset + i] = current_bg_color;
    }
    
    // Ultra-optimized screen redraw: use hardware scrolling when possible
    // Clear the entire screen first (fast operation)
    vbedbuff_clear(current_bg_color);
    
    // Redraw all characters from the updated buffer
    // Use optimized drawing with early exit for empty spaces
    for (size_t line = 0; line < total_lines; line++) {
        for (size_t col = 0; col < line_size; col++) {
            size_t buffer_index = line * line_size + col;
            char c = screen_buffer[buffer_index];
            uint32_t fg_color = fg_color_buffer[buffer_index];
            uint32_t bg_color = bg_color_buffer[buffer_index];
            
            // Skip drawing spaces with default background color (major optimization)
            if (c == ' ' && bg_color == current_bg_color) {
                continue;
            }
            
            // Draw the character using optimized pixel access
            unsigned char* glyph = font8x8_basic[(uint8_t)c];
            uint32_t start_x = col * 8;
            uint32_t start_y = line * 8;
            
            // Optimized character drawing with bounds checking
            for (uint32_t y = 0; y < 8; y++) {
                uint32_t pixel_y = start_y + y;
                if (pixel_y >= vbe_get_height()) break;
                
                for (uint32_t x = 0; x < 8; x++) {
                    uint32_t pixel_x = start_x + x;
                    if (pixel_x >= vbe_get_width()) break;
                    
                    // Fast bit test and color selection
                    uint32_t color = ((glyph[y] >> x) & 0x1) ? fg_color : bg_color;
                    vbedbuff_pixel(pixel_x, pixel_y, color);
                }
            }
        }
    }
}

// Put a character on the console
void vbetty_put_char(char c) {
    // Check for overflow at the very beginning
    if (vbetty_cursor_y > 1000 || vbetty_cursor_y == 4294967295) {
        vbetty_cursor_y = 0;
    }
    
    // Handle special characters
    if (c == '\n') {
        vbetty_force_hide_cursor();
        vbetty_cursor_x = 0;
        vbetty_cursor_y++;
        
        // Check if we need to scroll
        if (vbetty_cursor_y >= console_height_chars) {
            vbetty_scroll_up();
            vbetty_cursor_y = console_height_chars - 1;
        }
        return;
    }
    
    if (c == '\r') {
        vbetty_force_hide_cursor();
        vbetty_cursor_x = 0;
        return;
    }
    
    if (c == '\b') {
        vbetty_force_hide_cursor();
        if (vbetty_cursor_x > 0) {
            vbetty_cursor_x--;
        } else if (vbetty_cursor_y > 0) {
            vbetty_cursor_y--;
            vbetty_cursor_x = console_width_chars - 1;
        }
        // Erase the character by drawing a space
        vbetty_put_char(' ');
        if (vbetty_cursor_x > 0) {
            vbetty_cursor_x--; // Move back to the erased character's position
        }
        return;
    }
    
    // Check bounds
    if (vbetty_cursor_x >= console_width_chars) {
        vbetty_force_hide_cursor();
        vbetty_cursor_x = 0;
        vbetty_cursor_y++;
        
        // Check for overflow after increment
        if (vbetty_cursor_y >= console_height_chars) {
            vbetty_scroll_up();
            vbetty_cursor_y = console_height_chars - 1;
        }
    }
    
    // Check bounds before drawing
    if (vbetty_cursor_x >= console_width_chars || vbetty_cursor_y >= console_height_chars) {
        vbetty_force_hide_cursor();
        vbetty_cursor_x++;
        return;
    }
    
    // Save character and colors to buffer
    size_t buffer_index = vbetty_cursor_y * console_width_chars + vbetty_cursor_x;
    if (screen_buffer && fg_color_buffer && bg_color_buffer) {
        screen_buffer[buffer_index] = c;
        fg_color_buffer[buffer_index] = current_fg_color;
        bg_color_buffer[buffer_index] = current_bg_color;
    }
    
    // Draw the character
    unsigned char* glyph = font8x8_basic[(uint8_t)c];
    uint32_t start_x = vbetty_cursor_x * 8;
    uint32_t start_y = vbetty_cursor_y * 8;
    
    for (uint32_t y = 0; y < 8; y++) {
        for (uint32_t x = 0; x < 8; x++) {
            uint32_t pixel_x = start_x + x;
            uint32_t pixel_y = start_y + y;
            
            if (pixel_x < vbe_get_width() && pixel_y < vbe_get_height()) {
                uint32_t color = ((glyph[y] >> x) & 0x1) ? current_fg_color : current_bg_color;
                vbedbuff_pixel(pixel_x, pixel_y, color);
            }
        }
    }
    
    vbetty_cursor_x++;
    // Let PIT timer handle all screen updates for maximum performance
}

// Print a string to the console
void vbetty_print(const char* str) {
    while (*str) {
        vbetty_put_char(*str++);
    }
}

// Get cursor X position
uint32_t vbetty_get_cursor_x() {
    return vbetty_cursor_x;
}

// Get cursor Y position
uint32_t vbetty_get_cursor_y() {
    return vbetty_cursor_y;
}

// Set cursor position
void vbetty_set_cursor_pos(uint32_t x, uint32_t y) {
    // Сначала стираем старый курсор
    vbetty_force_hide_cursor();
    if (x < console_width_chars) {
        vbetty_cursor_x = x;
    }
    if (y < console_height_chars) {
        vbetty_cursor_y = y;
    }
}

// Update cursor blink state
void vbetty_update_cursor() {
    // Check if buffers are initialized
    if (!screen_buffer || !fg_color_buffer || !bg_color_buffer) {
        return;
    }
    
    // Курсор всегда горит - убираем мигание
    cursor_visible = true;
    
    // Redraw the character at cursor position
    if (vbetty_cursor_x < console_width_chars && vbetty_cursor_y < console_height_chars) {
        size_t buffer_index = vbetty_cursor_y * console_width_chars + vbetty_cursor_x;
        uint32_t start_x = vbetty_cursor_x * 8;
        uint32_t start_y = vbetty_cursor_y * 8;
        
        char c = screen_buffer[buffer_index];
        uint32_t fg_color = fg_color_buffer[buffer_index];
        uint32_t bg_color = bg_color_buffer[buffer_index];
        
        // Если позиция пустая, используем пробел
        if (c == 0) {
            c = ' ';
            fg_color = current_fg_color;
            bg_color = current_bg_color;
        }
        
        unsigned char* glyph = font8x8_basic[(uint8_t)c];
        
        for (uint32_t y = 0; y < 8; y++) {
            for (uint32_t x = 0; x < 8; x++) {
                uint32_t pixel_x = start_x + x;
                uint32_t pixel_y = start_y + y;
                
                if (pixel_x < vbe_get_width() && pixel_y < vbe_get_height()) {
                    // Курсор всегда горит - используем инвертированные цвета
                    uint32_t color = ((glyph[y] >> x) & 0x1) ? bg_color : fg_color;
                    vbedbuff_pixel(pixel_x, pixel_y, color);
                }
            }
        }
    }
}

// Show cursor
void vbetty_show_cursor() {
    cursor_visible = true;
    cursor_blink_counter = 0; // Reset counter when showing cursor
    
    // Immediately draw cursor at current position
    if (vbetty_cursor_x < console_width_chars && vbetty_cursor_y < console_height_chars) {
        size_t buffer_index = vbetty_cursor_y * console_width_chars + vbetty_cursor_x;
        uint32_t start_x = vbetty_cursor_x * 8;
        uint32_t start_y = vbetty_cursor_y * 8;
        
        char c = screen_buffer[buffer_index];
        uint32_t fg_color = fg_color_buffer[buffer_index];
        uint32_t bg_color = bg_color_buffer[buffer_index];
        
        unsigned char* glyph = font8x8_basic[(uint8_t)c];
        
        for (uint32_t y = 0; y < 8; y++) {
            for (uint32_t x = 0; x < 8; x++) {
                uint32_t pixel_x = start_x + x;
                uint32_t pixel_y = start_y + y;
                
                if (pixel_x < vbe_get_width() && pixel_y < vbe_get_height()) {
                    // Draw inverted colors for cursor (show cursor immediately)
                    uint32_t color = ((glyph[y] >> x) & 0x1) ? bg_color : fg_color;
                    vbedbuff_pixel(pixel_x, pixel_y, color);
                }
            }
        }
    }
}

// Hide cursor
void vbetty_hide_cursor() {
    cursor_visible = false;
}

// Force draw cursor at current position
void vbetty_force_draw_cursor() {
    if (!screen_buffer || !fg_color_buffer || !bg_color_buffer) {
        PrintfQEMU("ERROR: Buffers not initialized!\n");
        return;
    }
    
    if (vbetty_cursor_x >= console_width_chars || vbetty_cursor_y >= console_height_chars) {
        PrintfQEMU("ERROR: Cursor position out of bounds! (%u,%u) >= (%u,%u)\n", 
                   vbetty_cursor_x, vbetty_cursor_y, console_width_chars, console_height_chars);
        // Сбрасываем курсор в безопасную позицию
        vbetty_cursor_x = 0;
        vbetty_cursor_y = 0;
        return;
    }
    
    size_t buffer_index = vbetty_cursor_y * console_width_chars + vbetty_cursor_x;
    uint32_t start_x = vbetty_cursor_x * 8;
    uint32_t start_y = vbetty_cursor_y * 8;
    
    char c = screen_buffer[buffer_index];
    uint32_t fg_color = fg_color_buffer[buffer_index];
    uint32_t bg_color = bg_color_buffer[buffer_index];
    
    // Если позиция пустая, используем пробел
    if (c == 0) {
        c = ' ';
        fg_color = current_fg_color;
        bg_color = current_bg_color;
    }
    
    unsigned char* glyph = font8x8_basic[(uint8_t)c];
    
    for (uint32_t y = 0; y < 8; y++) {
        for (uint32_t x = 0; x < 8; x++) {
            uint32_t pixel_x = start_x + x;
            uint32_t pixel_y = start_y + y;
            
            if (pixel_x < vbe_get_width() && pixel_y < vbe_get_height()) {
                // Draw inverted colors for cursor
                uint32_t color = ((glyph[y] >> x) & 0x1) ? bg_color : fg_color;
                vbedbuff_pixel(pixel_x, pixel_y, color);
            }
        }
    }
}

// Force hide cursor by redrawing normal character
void vbetty_force_hide_cursor() {
    if (!screen_buffer || !fg_color_buffer || !bg_color_buffer) {
        return;
    }
    
    if (vbetty_cursor_x >= console_width_chars || vbetty_cursor_y >= console_height_chars) {
        return;
    }
    
    size_t buffer_index = vbetty_cursor_y * console_width_chars + vbetty_cursor_x;
    char c = screen_buffer[buffer_index];
    uint32_t fg_color = fg_color_buffer[buffer_index];
    uint32_t bg_color = bg_color_buffer[buffer_index];
    
    // Если позиция пустая, используем пробел
    if (c == 0) {
        c = ' ';
        fg_color = current_fg_color;
        bg_color = current_bg_color;
    }
    
    // Сохраняем текущие цвета и позицию
    uint32_t old_fg_color = current_fg_color;
    uint32_t old_bg_color = current_bg_color;
    uint32_t old_cursor_x = vbetty_cursor_x;
    uint32_t old_cursor_y = vbetty_cursor_y;
    
    // Устанавливаем цвета символа
    current_fg_color = fg_color;
    current_bg_color = bg_color;
    
    // Рисуем символ нормальными цветами напрямую на экране
    unsigned char* glyph = font8x8_basic[(uint8_t)c];
    uint32_t start_x = old_cursor_x * 8;
    uint32_t start_y = old_cursor_y * 8;
    
    for (uint32_t y = 0; y < 8; y++) {
        for (uint32_t x = 0; x < 8; x++) {
            uint32_t pixel_x = start_x + x;
            uint32_t pixel_y = start_y + y;
            
            if (pixel_x < vbe_get_width() && pixel_y < vbe_get_height()) {
                // Draw normal colors
                uint32_t color = ((glyph[y] >> x) & 0x1) ? fg_color : bg_color;
                vbedbuff_pixel(pixel_x, pixel_y, color);
            }
        }
    }
    
    // Восстанавливаем цвета и позицию
    current_fg_color = old_fg_color;
    current_bg_color = old_bg_color;
    vbetty_cursor_x = old_cursor_x;
    vbetty_cursor_y = old_cursor_y;
}

// 16-color palette (standard console colors)
static const uint32_t color_palette[16] = {
    0x000000, // 0: Black
    0x0000C4, // 1: Blue
    0x00C400, // 2: Green
    0x00C4C4, // 3: Cyan
    0xC40000, // 4: Red
    0xC400C4, // 5: Magenta
    0xC47E00, // 6: Brown/Orange
    0xC4C4C4, // 7: Light Gray
    0x4E4E4E, // 8: Dark Gray
    0x4E4EDC, // 9: Medium Blue
    0x4EDC4E, // 10: Light Green
    0x4EF3F3, // 11: Light Cyan
    0xDC4E4E, // 12: Light Red/Coral
    0xF34EF3, // 13: Pink/Light Magenta
    0xF3F34E, // 14: Yellow
    0xFFFFFF  // 15: White
};

// Helper function to convert hex digit to color number
static int hex_to_color_num(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0; // Default to black
}

// Helper function to parse color pair: <(bg_fg)>
static void parse_color_pair(const char* color_str) {
    if (strlen(color_str) >= 2) {
        int bg_color = hex_to_color_num(color_str[0]);
        int fg_color = hex_to_color_num(color_str[1]);
        
        // Set background and foreground colors
        vbetty_set_bg_color(color_palette[bg_color]);
        vbetty_set_fg_color(color_palette[fg_color]);
    }
}

// Helper function to print a number
static void print_number(int num, int base) {
    char buffer[32];
    char* ptr = buffer + 31;
    *ptr = '\0';
    
    if (num == 0) {
        vbetty_put_char('0');
        return;
    }
    
    bool negative = false;
    if (num < 0 && base == 10) {
        negative = true;
        num = -num;
    }
    
    while (num > 0) {
        int digit = num % base;
        if (digit < 10) {
            *--ptr = '0' + digit;
        } else {
            *--ptr = 'a' + (digit - 10);
        }
        num /= base;
    }
    
    if (negative) {
        *--ptr = '-';
    }
    
    vbetty_print(ptr);
}

// Helper function to print an unsigned number
static void print_unsigned(uint32_t num, int base, int width = 0, bool zero_pad = false) {
    char buffer[32];
    char* ptr = buffer + 31;
    *ptr = '\0';
    
    if (num == 0) {
        if (width > 0) {
            for (int i = 0; i < width - 1; i++) {
                if (zero_pad) {
                    vbetty_put_char('0');
                } else {
                    vbetty_put_char(' ');
                }
            }
        }
        vbetty_put_char('0');
        return;
    }
    
    while (num > 0) {
        int digit = num % base;
        if (digit < 10) {
            *--ptr = '0' + digit;
        } else {
            *--ptr = 'a' + (digit - 10);
        }
        num /= base;
    }
    
    int len = strlen(ptr);
    if (width > len) {
        for (int i = 0; i < width - len; i++) {
            if (zero_pad) {
                vbetty_put_char('0');
            } else {
                vbetty_put_char(' ');
            }
        }
    }
    
    vbetty_print(ptr);
}

// kprintf implementation with format support and color escape sequences
int kprintf(const char* format, ...) {
    acquire(&vbelock);
    
    va_list args;
    va_start(args, format);
    
    int chars_written = 0;
    const char* ptr = format;
    
    while (*ptr) {
        if (*ptr == '<' && *(ptr + 1) == '(') {
            // Color escape sequence: <(bg_fg)>text
            ptr += 2; // Skip '<('
            
            char color_pair[3] = {0};
            int color_len = 0;
            
            // Extract color pair (background and foreground)
            while (*ptr && *ptr != ')' && color_len < 2) {
                color_pair[color_len++] = *ptr++;
            }
            
            if (*ptr == ')') {
                ptr++; // Skip ')'
                
                // Look for closing '>'
                if (*ptr == '>') {
                    ptr++; // Skip '>'
                    
                    // Apply background and foreground colors
                    parse_color_pair(color_pair);
                    
                    // Continue processing the text after the color sequence
                    continue;
                }
            }
        }
        
        if (*ptr == '%') {
            ptr++; // Skip '%'
            
            // Parse width and zero-pad flags
            int width = 0;
            bool zero_pad = false;
            
            // Check for zero-pad flag
            if (*ptr == '0') {
                zero_pad = true;
                ptr++;
            }
            
            // Parse width
            while (*ptr >= '0' && *ptr <= '9') {
                width = width * 10 + (*ptr - '0');
                ptr++;
            }
            
            switch (*ptr) {
                case 'd':
                case 'i': {
                    int num = va_arg(args, int);
                    print_number(num, 10);
                    chars_written++;
                    break;
                }
                case 'u': {
                    uint32_t num = va_arg(args, uint32_t);
                    print_unsigned(num, 10, width, zero_pad);
                    chars_written++;
                    break;
                }
                case 'x':
                case 'X': {
                    uint32_t num = va_arg(args, uint32_t);
                    print_unsigned(num, 16, width, zero_pad);
                    chars_written++;
                    break;
                }
                case 'o': {
                    uint32_t num = va_arg(args, uint32_t);
                    print_unsigned(num, 8, width, zero_pad);
                    chars_written++;
                    break;
                }
                case 'c': {
                    char c = va_arg(args, int);
                    vbetty_put_char(c);
                    chars_written++;
                    break;
                }
                case 's': {
                    const char* str = va_arg(args, const char*);
                    if (str) {
                        vbetty_print(str);
                        chars_written += strlen(str);
                    }
                    break;
                }
                case 'p': {
                    void* ptr_val = va_arg(args, void*);
                    vbetty_print("0x");
                    print_unsigned((uint32_t)(uint64_t)ptr_val, 16);
                    chars_written += 2;
                    break;
                }
                case '%': {
                    vbetty_put_char('%');
                    chars_written++;
                    break;
                }
                default:
                    // Unknown format, just print the character
                    vbetty_put_char(*ptr);
                    chars_written++;
                    break;
            }
        } else {
            vbetty_put_char(*ptr);
            chars_written++;
        }
        
        ptr++;
    }
    
    va_end(args);
    release(&vbelock);
    return chars_written;
} 

// Ensure cursor is at the beginning of a new line
void vbetty_ensure_newline() {
    if (vbetty_cursor_x != 0) {
        vbetty_put_char('\n');
    }
} 