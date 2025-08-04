#include <vbe.h>
#include <debug.h>
#include <string.h>

// VBE framebuffer information
uint32_t* framebuffer_addr = nullptr;
uint32_t fb_width = 0;
uint32_t fb_height = 0;
uint32_t fb_pitch = 0;
uint32_t fb_bpp = 0;
bool framebuffer_initialized = false;

// Initialize VBE framebuffer
void vbe_init(uint64_t addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
    PrintfQEMU("VBE init called with addr: 0x%llx, width: %u, height: %u, pitch: %u, bpp: %u\n", 
               (unsigned long long)addr, width, height, pitch, bpp);
    
    framebuffer_addr = (uint32_t*)addr;
    fb_width = width;
    fb_height = height;
    fb_pitch = pitch;
    fb_bpp = bpp;
    framebuffer_initialized = true;
    
    PrintfQEMU("VBE initialized:\n");
    PrintfQEMU("Width: %u\n", fb_width);
    PrintfQEMU("Height: %u\n", fb_height);
    PrintfQEMU("Pitch: %u\n", fb_pitch);
    PrintfQEMU("BPP: %u\n", fb_bpp);
    PrintfQEMU("Addr: 0x%llx\n", (unsigned long long)addr);
    PrintfQEMU("framebuffer_addr pointer: 0x%llx\n", (unsigned long long)(uint64_t)framebuffer_addr);
}

// Draw a single pixel
void vbe_pixel(int x, int y, uint32_t color) {
    if (!framebuffer_initialized || !framebuffer_addr) {
        return;
    }
    
    if (x < 0 || (uint32_t)x >= fb_width || y < 0 || (uint32_t)y >= fb_height) {
        return;
    }

    uint32_t offset = y * fb_pitch + x * (fb_bpp / 8);
    uint32_t* pixel_addr = (uint32_t*)((uint8_t*)framebuffer_addr + offset);
    *pixel_addr = color;
}

// Clear entire screen
void vbe_clear(uint32_t color) {
    if (!framebuffer_initialized || !framebuffer_addr) {
        return;
    }
    
    // Fill each pixel
    for (uint32_t y = 0; y < fb_height; y++) {
        for (uint32_t x = 0; x < fb_width; x++) {
            vbe_pixel(x, y, color);
        }
    }
}

// Fill rectangle
void vbe_fill_rect(int x, int y, int width, int height, uint32_t color) {
    if (!framebuffer_initialized || !framebuffer_addr) {
        return;
    }
    
    for (int py = y; py < y + height; py++) {
        for (int px = x; px < x + width; px++) {
            vbe_pixel(px, py, color);
        }
    }
}

// Draw line using Bresenham's algorithm
void vbe_line(int x1, int y1, int x2, int y2, uint32_t color) {
    if (!framebuffer_initialized || !framebuffer_addr) {
        return;
    }
    
    int dx = (x2 > x1) ? (x2 - x1) : (x1 - x2);
    int dy = (y2 > y1) ? (y2 - y1) : (y1 - y2);
    int sx = (x1 < x2) ? 1 : -1;
    int sy = (y1 < y2) ? 1 : -1;
    int err = dx - dy;
    
    int x = x1, y = y1;
    
    while (true) {
        vbe_pixel(x, y, color);
        
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

// Draw circle using midpoint circle algorithm
void vbe_circle(int center_x, int center_y, int radius, uint32_t color) {
    if (!framebuffer_initialized || !framebuffer_addr) {
        return;
    }
    
    int x = radius;
    int y = 0;
    int err = 0;
    
    while (x >= y) {
        vbe_pixel(center_x + x, center_y + y, color);
        vbe_pixel(center_x + y, center_y + x, color);
        vbe_pixel(center_x - y, center_y + x, color);
        vbe_pixel(center_x - x, center_y + y, color);
        vbe_pixel(center_x - x, center_y - y, color);
        vbe_pixel(center_x - y, center_y - x, color);
        vbe_pixel(center_x + y, center_y - x, color);
        vbe_pixel(center_x + x, center_y - y, color);
        
        if (err <= 0) {
            y += 1;
            err += 2*y + 1;
        }
        if (err > 0) {
            x -= 1;
            err -= 2*x + 1;
        }
    }
}

// Utility functions
bool vbe_is_initialized() {
    return framebuffer_initialized;
}

uint32_t vbe_get_width() {
    return fb_width;
}

uint32_t vbe_get_height() {
    return fb_height;
}

uint32_t vbe_get_pitch() {
    return fb_pitch;
}

uint32_t vbe_get_bpp() {
    return fb_bpp;
} 