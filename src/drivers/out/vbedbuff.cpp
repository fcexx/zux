#include <vbedbuff.h>
#include <vbe.h>
#include <heap.h>
#include <debug.h>
#include <string.h>

// External reference to framebuffer address
extern uint32_t* framebuffer_addr;

// Back buffer for double buffering
static uint32_t* back_buffer = nullptr;
static bool double_buffering_initialized = false;

// Initialize double buffering
void vbedbuff_init() {
    PrintQEMU("vbedbuff_init() called\n");
    
    if (double_buffering_initialized) {
        PrintQEMU("Double buffering already initialized\n");
        return;
    }
    
    if (!vbe_is_initialized()) {
        PrintQEMU("VBE not initialized, cannot initialize double buffering\n");
        return;
    }
    
    // Allocate back buffer
    size_t buffer_size = vbe_get_height() * vbe_get_pitch();
    PrintfQEMU("Attempting to allocate back buffer: %llu bytes\n", (unsigned long long)buffer_size);
    PrintfQEMU("VBE height: %u, pitch: %u\n", vbe_get_height(), vbe_get_pitch());
    
    back_buffer = (uint32_t*)kmalloc(buffer_size);
    
    if (!back_buffer) {
        PrintQEMU("Failed to allocate back buffer for double buffering\n");
        PrintfQEMU("kmalloc returned nullptr for size: %llu\n", (unsigned long long)buffer_size);
        return;
    }
    
    PrintfQEMU("Successfully allocated back buffer at: 0x%x\n", (unsigned long long)(uint64_t)back_buffer);
    
    double_buffering_initialized = true;
    PrintfQEMU("Double buffering initialized with back buffer size: %llu bytes\n", 
               (unsigned long long)buffer_size);
}

// Draw pixel to back buffer
void vbedbuff_pixel(int x, int y, uint32_t color) {
    if (!double_buffering_initialized || !back_buffer) {
        // Fallback to direct VBE if double buffering not available
        vbe_pixel(x, y, color);
        return;
    }
    
    if (x < 0 || (uint32_t)x >= vbe_get_width() || y < 0 || (uint32_t)y >= vbe_get_height()) {
        return;
    }

    uint32_t offset = y * vbe_get_pitch() + x * (vbe_get_bpp() / 8);
    uint32_t* pixel_addr = (uint32_t*)((uint8_t*)back_buffer + offset);
    *pixel_addr = color;
}

// Clear back buffer
void vbedbuff_clear(uint32_t color) {
    if (!double_buffering_initialized || !back_buffer) {
        // Fallback to direct VBE
        vbe_clear(color);
        return;
    }
    
    // Fill back buffer with color using optimized memset-like approach
    uint32_t* buffer_ptr = (uint32_t*)back_buffer;
    size_t total_pixels = vbe_get_width() * vbe_get_height();
    
    // Use word-sized writes for better performance
    for (size_t i = 0; i < total_pixels; i++) {
        buffer_ptr[i] = color;
    }
}

// Fill rectangle in back buffer
void vbedbuff_fill_rect(int x, int y, int width, int height, uint32_t color) {
    if (!double_buffering_initialized || !back_buffer) {
        // Fallback to direct VBE
        vbe_fill_rect(x, y, width, height, color);
        return;
    }
    
    for (int py = y; py < y + height; py++) {
        for (int px = x; px < x + width; px++) {
            vbedbuff_pixel(px, py, color);
        }
    }
}

// Draw line in back buffer
void vbedbuff_line(int x1, int y1, int x2, int y2, uint32_t color) {
    if (!double_buffering_initialized || !back_buffer) {
        // Fallback to direct VBE
        vbe_line(x1, y1, x2, y2, color);
        return;
    }
    
    int dx = (x2 > x1) ? (x2 - x1) : (x1 - x2);
    int dy = (y2 > y1) ? (y2 - y1) : (y1 - y2);
    int sx = (x1 < x2) ? 1 : -1;
    int sy = (y1 < y2) ? 1 : -1;
    int err = dx - dy;
    
    int x = x1, y = y1;
    
    while (true) {
        vbedbuff_pixel(x, y, color);
        
        if (x == x2 && y == y2) break;
        
        int e2 = 2 * err;
        if (e2 > -dy) {
            err -= dy;
            x += sx;
        }
        if (e2 < dx) {
            err += dx;
            y += sy;
        }
    }
}

// Draw circle in back buffer
void vbedbuff_circle(int center_x, int center_y, int radius, uint32_t color) {
    if (!double_buffering_initialized || !back_buffer) {
        // Fallback to direct VBE
        vbe_circle(center_x, center_y, radius, color);
        return;
    }
    
    int x = radius;
    int y = 0;
    int err = 0;

    while (x >= y) {
        vbedbuff_pixel(center_x + x, center_y + y, color);
        vbedbuff_pixel(center_x + y, center_y + x, color);
        vbedbuff_pixel(center_x - y, center_y + x, color);
        vbedbuff_pixel(center_x - x, center_y + y, color);
        vbedbuff_pixel(center_x - x, center_y - y, color);
        vbedbuff_pixel(center_x - y, center_y - x, color);
        vbedbuff_pixel(center_x + y, center_y - x, color);
        vbedbuff_pixel(center_x + x, center_y - y, color);

        if (err <= 0) {
            y++;
            err += 2 * y + 1;
        }
        if (err > 0) {
            x--;
            err -= 2 * x + 1;
        }
    }
}

// Copy back buffer to front buffer (flip)
void vbedbuff_flip() {
    if (!double_buffering_initialized || !back_buffer) {
        return;
    }
    
    // Use direct memory copy for better performance
    // This assumes both buffers have the same format and size
    size_t buffer_size = vbe_get_height() * vbe_get_pitch();
    memcpy(framebuffer_addr, back_buffer, buffer_size);
}

// Swap buffers (if we had multiple back buffers)
void vbedbuff_swap() {
    // For now, just flip since we only have one back buffer
    vbedbuff_flip();
}

// Clear only back buffer
void vbedbuff_clear_back_buffer(uint32_t color) {
    if (!double_buffering_initialized || !back_buffer) {
        return;
    }
    
    // Fill back buffer with color
    for (uint32_t y = 0; y < vbe_get_height(); y++) {
        for (uint32_t x = 0; x < vbe_get_width(); x++) {
            vbedbuff_pixel(x, y, color);
        }
    }
}

// Utility functions
bool vbedbuff_is_initialized() {
    return double_buffering_initialized;
}

uint32_t* vbedbuff_get_back_buffer() {
    return back_buffer;
} 