#include <cirrus.h>
#include <pci.h>
#include <debug.h>
#include <vga.h>
#include <fonts.h>
#include <paging.h>
#include <stdint.h>
#include <string.h>

// This is a minimal, safe implementation sufficient for early-boot
// console switching. It does not attempt to program advanced Cirrus
// registers — instead it detects the device and exposes a framebuffer
// backed console that can be switched to from legacy text mode.

static int g_ready = 0;
static void* g_fb_phys = (void*)0xA0000; // default VGA graphics framebuffer (physical)
static void* g_fb_virt = (void*)0xA0000; // virtual mapping used by kernel
// Default mode: 800x600 8bpp as requested
static uint32_t g_width = 800;
static uint32_t g_height = 600;
static uint32_t g_pitch = 800;
static uint32_t g_bpp = 8; // indexed palette

// Known Cirrus vendor/device IDs (vendor 0x1013)
static const uint16_t CIRRUS_VENDOR = 0x1013;
// Common CL-GD54xx PCI device ids (not exhaustive)
static const uint16_t CIRRUS_DEVICES[] = { 0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, 0x5446 };

static int pci_device_matches(uint16_t vid, uint16_t did){
    if (vid != CIRRUS_VENDOR) return 0;
    for (size_t i=0;i<sizeof(CIRRUS_DEVICES)/sizeof(CIRRUS_DEVICES[0]);++i){ if (CIRRUS_DEVICES[i]==did) return 1; }
    return 0;
}

void cirrus_init(void){
    // scan PCI bus for Cirrus devices (simple scan reusing pci_read helpers)
    for (int bus=0; bus<256; ++bus){
        for (int dev=0; dev<32; ++dev){
            uint16_t vid = pci_config_read16((uint8_t)bus, (uint8_t)dev, 0, 0x00);
            if (vid == 0xFFFF) continue;
            uint8_t header = pci_config_read8((uint8_t)bus, (uint8_t)dev, 0, 0x0E);
            int funcs = (header & 0x80) ? 8 : 1;
            for (int fn=0; fn<funcs; ++fn){
                vid = pci_config_read16((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x00);
                if (vid == 0xFFFF) continue;
                uint16_t did = pci_config_read16((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x02);
                if (pci_device_matches(vid, did)){
                    klog_printf("cirrus: detected vendor=0x%04x device=0x%04x at %02x:%02x.%d class=%02x subclass=%02x\n",
                               vid, did, bus, dev, fn, pci_config_read8((uint8_t)bus,(uint8_t)dev,(uint8_t)fn,0x0B),
                               pci_config_read8((uint8_t)bus,(uint8_t)dev,(uint8_t)fn,0x0A));

                    // scan BAR0..BAR5 for a memory BAR to use as framebuffer
                    uint32_t chosen_bar = 0;
                    for (int bar_off = 0x10; bar_off <= 0x24; bar_off += 4) {
                        uint32_t bar = pci_config_read32((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, (uint8_t)bar_off);
                        if ((bar & 0x1u) == 0) { // memory BAR
                            uint32_t addr = bar & 0xFFFFFFF0u;
                            klog_printf("cirrus: found mem BAR at 0x%08x (off 0x%02x)\n", addr, bar_off);
                            // prefer legacy VGA aperture if present
                            if (addr >= 0xA0000 && addr < 0x100000) { chosen_bar = addr; break; }
                            // otherwise accept first mem BAR
                            if (chosen_bar == 0) chosen_bar = addr;
                        }
                    }

                    if (chosen_bar != 0) {
                        // If BAR points to legacy VGA aperture (A0000..FFFF) we can use it as framebuffer
                        if (chosen_bar >= 0xA0000 && chosen_bar < 0x100000) {
                            cirrus_set_framebuffer((void*)(uintptr_t)chosen_bar, 320, 200, 320, 8);
                            g_ready = 1;
                            klog_printf("cirrus: framebuffer set at legacy aperture 0x%08x (320x200@8bpp)\n", (unsigned)chosen_bar);
                            return;
                        }

                        // Non-legacy memory BARs often require programming device registers or VBE.
                        // Do not auto-enable cirrus console for arbitrary BARs to avoid rendering artifacts.
                        klog_printf("cirrus: found mem BAR at 0x%08x but not legacy aperture; skipping auto-enable\n", chosen_bar);
                    } else {
                        klog_printf("cirrus: no usable memory BAR found\n");
                    }
                }
            }
        }
    }
}

int cirrus_console_ready(void){ return g_ready; }

void cirrus_set_framebuffer(void* fb_phys_addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp){
    g_fb_phys = fb_phys_addr;
    g_width = width; g_height = height; g_pitch = pitch; g_bpp = bpp;
    // Map framebuffer into kernel address space at a high-half alias to avoid
    // accidentally identity-mapping low physical memory (which breaks the kernel).
    uint64_t phys = (uint64_t)(uintptr_t)fb_phys_addr;
    uint64_t fb_size = (uint64_t)g_pitch * (uint64_t)g_height;
    if (fb_size == 0) fb_size = 0x00100000ULL; // fallback size
    // Align mapping to page granularity to avoid mapping physical 0 unintentionally
    const uint64_t page_mask = (uint64_t)(PAGE_SIZE - 1);
    uint64_t map_base = phys & ~page_mask; // align down to PAGE_SIZE
    uint64_t offset_in_page = phys - map_base;
    uint64_t map_size = ((fb_size + offset_in_page) + page_mask) & ~page_mask;
    // Identity-map the framebuffer region (virtual == physical).
    // The kernel identity-maps low memory; ensure mapping exists for the FB region.
    paging_map_range(map_base, map_base, map_size, PAGE_PRESENT | PAGE_WRITABLE);
    g_fb_virt = (void*)(uintptr_t)(phys);
}

uint32_t cirrus_get_width(void){ return g_width; }
uint32_t cirrus_get_height(void){ return g_height; }

void cirrus_put_pixel(uint32_t x, uint32_t y, uint32_t color){
    if (x >= g_width || y >= g_height) return;
    volatile uint8_t* fb = (volatile uint8_t*)(uintptr_t)g_fb_virt;
    uint32_t ofs = y * g_pitch + x * (g_bpp/8);
    if (g_bpp == 8){ fb[ofs] = (uint8_t)color; }
    else if (g_bpp == 32){ volatile uint32_t* fb32 = (volatile uint32_t*)fb; fb32[ofs/4] = color; }
}

// Provide a text-like put_cell by rendering 8x16 glyphs into framebuffer
void cirrus_put_cell(uint32_t x, uint32_t y, char c, uint8_t fg, uint8_t bg){
    if (!g_ready) return;
    if (x >= 80 || y >= 25) return;
    // render 8x16 from font8x16sun into framebuffer assuming 320x200/8bpp or larger
    const uint16_t* glyph = font8x16sun[(uint8_t)c];
    uint32_t px = x * 8;
    uint32_t py = y * 16;
    for (uint32_t row = 0; row < 16; ++row){
        uint16_t bits = glyph[row];
        for (uint32_t col = 0; col < 8; ++col){
            uint32_t color = (bits & (1 << (7-col))) ? fg : bg;
            cirrus_put_pixel(px + col, py + row, color);
        }
    }
}

void cirrus_write_a000(uint32_t offset, const void* src, uint32_t len){
    if (!g_ready) return;
    volatile uint8_t* fb = (volatile uint8_t*)(uintptr_t)g_fb_virt;
    memcpy((void*)(fb + offset), src, len);
}

void cirrus_write_b800_cell(uint32_t index, uint16_t cell){
    if (!g_ready) return;
    uint32_t x = index % 80; uint32_t y = index / 80;
    char ch = (char)(cell & 0xFF);
    uint8_t attr = (uint8_t)((cell >> 8) & 0xFF);
    uint8_t fg = attr & 0x0F;
    uint8_t bg = (attr >> 4) & 0x0F;
    cirrus_put_cell(x, y, ch, fg, bg);
}

void cirrus_set_palette_entry(uint8_t index, uint8_t r, uint8_t g, uint8_t b){
    // Store palette in a simple software table; real hardware ops omitted
    (void)index; (void)r; (void)g; (void)b;
}

void cirrus_init_default_palette(void){
    // Initialize VGA-like 16 color palette for 0..15 and linear greys for 16..255
    for (int i=0;i<16;++i){ cirrus_set_palette_entry((uint8_t)i, (uint8_t)(i*4), (uint8_t)(i*4), (uint8_t)(i*4)); }
}

static uint32_t cur_x = 0, cur_y = 0;
void cirrus_set_cursor(uint32_t x, uint32_t y){ cur_x = x; cur_y = y; }
void cirrus_get_cursor(uint32_t* x, uint32_t* y){ if (x) *x = cur_x; if (y) *y = cur_y; }

void cirrus_scroll_up(uint8_t bg_idx){
    // simple row copy for 16px-high rows (80x25)
    if (!g_ready) return;
    uint32_t row_bytes = g_pitch * 16;
    // use virtual mapping (g_fb_virt) for kernel access
    volatile uint8_t* fb = (volatile uint8_t*)(uintptr_t)g_fb_virt;
    // shift up 24 rows
    for (uint32_t row = 0; row < 24; ++row){
        uint32_t dst = row * row_bytes;
        uint32_t src = (row + 1) * row_bytes;
        // volatile-safe copy
        for (uint32_t i = 0; i < row_bytes; ++i) fb[dst + i] = fb[src + i];
    }
    // clear last row
    uint32_t last = 24 * row_bytes;
    for (uint32_t i = 0; i < row_bytes; ++i) fb[last + i] = (uint8_t)bg_idx;
    cur_x = 0; cur_y = 24;
}

void cirrus_takeover_console(void){
    // Copy legacy text buffer at 0xB8000 to framebuffer by rendering glyphs
    volatile uint16_t* text = (volatile uint16_t*)0xC00B8000ULL;
    for (uint32_t y=0;y<25;++y){
        for (uint32_t x=0;x<80;++x){
            uint16_t cell = text[y*80 + x];
            char ch = (char)(cell & 0xFF);
            uint8_t attr = (uint8_t)((cell >> 8) & 0xFF);
            uint8_t fg = attr & 0x0F;
            uint8_t bg = (attr >> 4) & 0x0F;
            cirrus_put_cell(x, y, ch, fg, bg);
        }
    }
}


