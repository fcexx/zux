// Cirrus Logic CL-GD54xx (GD5446) simple PCI/LFB driver
// C++ implementation to link with the rest of the kernel

#include <stdint.h>
#include <stddef.h>
#include <debug.h>   // даёт outb/inb/outl/inl, klog_printf
#include <vbe.h>     // vbe_init / vbec_init_console и т.д.
#include <paging.h>  // paging_map_range

// already have declarations from included headers debug.h vbe.h paging.h

extern "C" void clgd54xx_init();
extern "C" int clgd54xx_set_mode(unsigned int width, unsigned int height, unsigned int bpp);
extern "C" int clgd54xx_set_best_mode(void);



static uint16_t cgraph_svgacolor[] = {0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x4005, 0x0506,
    0x0f07, 0xff08, 0x0009, 0x000a, 0x000b, 0xffff};

// 640x480x8
static uint16_t cseq_640x480x8[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1107, 0x580b, 0x580c, 0x580d,
  0x580e, 0x0412, 0x0013, 0x2017, 0x331b, 0x331c, 0x331d, 0x331e, 0xffff};
static uint16_t ccrtc_640x480x8[] = {0x2c11, 0x5f00, 0x4f01, 0x4f02, 0x8003, 0x5204, 0x1e05, 0x0b06,
   0x3e07, 0x4009, 0x000c, 0x000d, 0xea10, 0xdf12, 0x5013, 0x4014,
   0xdf15, 0x0b16, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};
// 640x480x16/15
static uint16_t cseq_640x480x16[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1707, 0x580b, 0x580c, 0x580d,
   0x580e, 0x0412, 0x0013, 0x2017, 0x331b, 0x331c, 0x331d, 0x331e, 0xffff};
static uint16_t ccrtc_640x480x16[] = {0x2c11, 0x5f00, 0x4f01, 0x4f02, 0x8003, 0x5204, 0x1e05, 0x0b06,
    0x3e07, 0x4009, 0x000c, 0x000d, 0xea10, 0xdf12, 0xa013, 0x4014,
    0xdf15, 0x0b16, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};
// 640x480x24
static uint16_t cseq_640x480x24[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1507, 0x580b, 0x580c, 0x580d,
   0x580e, 0x0412, 0x0013, 0x2017, 0x331b, 0x331c, 0x331d, 0x331e, 0xffff};
static uint16_t ccrtc_640x480x24[] = {0x2c11, 0x5f00, 0x4f01, 0x4f02, 0x8003, 0x5204, 0x1e05, 0x0b06,
    0x3e07, 0x4009, 0x000c, 0x000d, 0xea10, 0xdf12, 0xf013, 0x4014,
    0xdf15, 0x0b16, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};

// 800x600x8
static uint16_t cseq_800x600x8[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1107, 0x230b, 0x230c, 0x230d,
  0x230e, 0x0412, 0x0013, 0x2017, 0x141b, 0x141c, 0x141d, 0x141e, 0xffff};
static uint16_t ccrtc_800x600x8[] = {0x2311, 0x7d00, 0x6301, 0x6302, 0x8003, 0x6b04, 0x1a05, 0x9806,
   0xf007, 0x6009, 0x000c, 0x000d, 0x7d10, 0x5712, 0x6413, 0x4014,
   0x5715, 0x9816, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};
// 800x600x16/15
static uint16_t cseq_800x600x16[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1707, 0x230b, 0x230c, 0x230d,
   0x230e, 0x0412, 0x0013, 0x2017, 0x141b, 0x141c, 0x141d, 0x141e, 0xffff};
static uint16_t ccrtc_800x600x16[] = {0x2311, 0x7d00, 0x6301, 0x6302, 0x8003, 0x6b04, 0x1a05, 0x9806,
    0xf007, 0x6009, 0x000c, 0x000d, 0x7d10, 0x5712, 0xc813, 0x4014,
    0x5715, 0x9816, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};
// 800x600x24
static uint16_t cseq_800x600x24[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1507, 0x230b, 0x230c, 0x230d,
   0x230e, 0x0412, 0x0013, 0x2017, 0x141b, 0x141c, 0x141d, 0x141e, 0xffff};
static uint16_t ccrtc_800x600x24[] = {0x2311, 0x7d00, 0x6301, 0x6302, 0x8003, 0x6b04, 0x1a05, 0x9806,
    0xf007, 0x6009, 0x000c, 0x000d, 0x7d10, 0x5712, 0x2c13, 0x4014,
    0x5715, 0x9816, 0xc317, 0xff18, 0x001a, 0x321b, 0x001d, 0xffff};

// 1024x768x8
static uint16_t cseq_1024x768x8[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1107, 0x760b, 0x760c, 0x760d,
   0x760e, 0x0412, 0x0013, 0x2017, 0x341b, 0x341c, 0x341d, 0x341e, 0xffff};
static uint16_t ccrtc_1024x768x8[] = {0x2911, 0xa300, 0x7f01, 0x7f02, 0x8603, 0x8304, 0x9405, 0x2406,
    0xf507, 0x6009, 0x000c, 0x000d, 0x0310, 0xff12, 0x8013, 0x4014,
    0xff15, 0x2416, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};
// 1024x768x16/15
static uint16_t cseq_1024x768x16[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1707, 0x760b, 0x760c, 0x760d,
    0x760e, 0x0412, 0x0013, 0x2017, 0x341b, 0x341c, 0x341d, 0x341e, 0xffff};
static uint16_t ccrtc_1024x768x16[] = {0x2911, 0xa300, 0x7f01, 0x7f02, 0x8603, 0x8304, 0x9405, 0x2406,
     0xf507, 0x6009, 0x000c, 0x000d, 0x0310, 0xff12, 0x0013, 0x4014,
     0xff15, 0x2416, 0xc317, 0xff18, 0x001a, 0x321b, 0x001d, 0xffff};
// 1024x768x24
static uint16_t cseq_1024x768x24[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1507, 0x760b, 0x760c, 0x760d,
    0x760e, 0x0412, 0x0013, 0x2017, 0x341b, 0x341c, 0x341d, 0x341e, 0xffff};
static uint16_t ccrtc_1024x768x24[] = {0x2911, 0xa300, 0x7f01, 0x7f02, 0x8603, 0x8304, 0x9405, 0x2406,
     0xf507, 0x6009, 0x000c, 0x000d, 0x0310, 0xff12, 0x8013, 0x4014,
     0xff15, 0x2416, 0xc317, 0xff18, 0x001a, 0x321b, 0x001d, 0xffff};

// 1280x1024x8
static uint16_t cseq_1280x1024x8[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1107, 0x760b, 0x760c, 0x760d,
    0x760e, 0x0412, 0x0013, 0x2017, 0x341b, 0x341c, 0x341d, 0x341e, 0xffff};
static uint16_t ccrtc_1280x1024x8[] = {0x2911, 0xc300, 0x9f01, 0x9f02, 0x8603, 0x8304, 0x9405, 0x2406,
     0xf707, 0x6009, 0x000c, 0x000d, 0x0310, 0xff12, 0xa013, 0x4014,
     0xff15, 0x2416, 0xc317, 0xff18, 0x001a, 0x221b, 0x001d, 0xffff};
// 1280x1024x16/15
static uint16_t cseq_1280x1024x16[] = {0x0300, 0x2101, 0x0f02, 0x0003, 0x0e04, 0x1707, 0x760b, 0x760c, 0x760d,
     0x760e, 0x0412, 0x0013, 0x2017, 0x341b, 0x341c, 0x341d, 0x341e, 0xffff};
static uint16_t ccrtc_1280x1024x16[] = {0x2911, 0xc300, 0x9f01, 0x9f02, 0x8603, 0x8304, 0x9405, 0x2406,
      0xf707, 0x6009, 0x000c, 0x000d, 0x0310, 0xff12, 0x4013, 0x4014,
      0xff15, 0x2416, 0xc317, 0xff18, 0x001a, 0x321b, 0x001d, 0xffff};

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static inline uint32_t pci_cfg_addr(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off)
{
    return (uint32_t)(0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)fn << 8) | (off & 0xFC));
}

static uint32_t pci_read32_raw(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off)
{
    uint32_t a = pci_cfg_addr(bus, dev, fn, off);
    outl(PCI_CONFIG_ADDRESS, a);
    return inl(PCI_CONFIG_DATA);
}

static uint16_t pci_read16_raw(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off)
{
    uint32_t v = pci_read32_raw(bus, dev, fn, off & 0xFC);
    return (uint16_t)((v >> ((off & 2) * 8)) & 0xFFFF);
}

static uint8_t pci_read8_raw(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off)
{
    uint32_t v = pci_read32_raw(bus, dev, fn, off & 0xFC);
    return (uint8_t)((v >> ((off & 3) * 8)) & 0xFF);
}

static void pci_write32_raw(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off, uint32_t val)
{
    uint32_t a = pci_cfg_addr(bus, dev, fn, off);
    outl(PCI_CONFIG_ADDRESS, a);
    outl(PCI_CONFIG_DATA, val);
}

#define CIRRUS_VENDOR_ID  0x1013
#define CIRRUS_DEVICE_ID  0x00B8 /* GD5446 */

static inline int bar_is_mem(uint32_t bar) { return (bar & 0x1u) == 0; }
static inline uint64_t bar_addr(uint32_t bar_lo, uint32_t bar_hi)
{
    uint64_t base = (uint64_t)(bar_lo & ~0xFu);
    if (((bar_lo >> 1) & 0x3u) == 0x2u) base |= ((uint64_t)bar_hi) << 32;
    return base;
}

static void clgd_print_device(uint8_t bus, uint8_t dev, uint8_t fn)
{
    uint16_t vendor = pci_read16_raw(bus, dev, fn, 0x00);
    uint16_t device = pci_read16_raw(bus, dev, fn, 0x02);
    uint8_t class_code = pci_read8_raw(bus, dev, fn, 0x0B);
    uint8_t subclass = pci_read8_raw(bus, dev, fn, 0x0A);
    uint8_t prog_if = pci_read8_raw(bus, dev, fn, 0x09);
    uint8_t header = pci_read8_raw(bus, dev, fn, 0x0E);
    klog_printf("cirrus: %02x:%02x.%x vendor=%04x device=%04x class=%02x subclass=%02x prog_if=%02x header=%02x\n",
        bus, dev, fn, vendor, device, class_code, subclass, prog_if, header);
}

static int clgd_find(uint8_t *out_bus, uint8_t *out_dev, uint8_t *out_fn)
{
    for (uint8_t bus = 0; bus < 0xFF; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            uint16_t vid = pci_read16_raw(bus, dev, 0, 0x00);
            if (vid == 0xFFFF) continue;
            uint8_t hdr = pci_read8_raw(bus, dev, 0, 0x0E);
            uint8_t fnc = (hdr & 0x80) ? 8 : 1;
            for (uint8_t fn = 0; fn < fnc; ++fn) {
                vid = pci_read16_raw(bus, dev, fn, 0x00);
                if (vid == 0xFFFF) continue;
                uint16_t did = pci_read16_raw(bus, dev, fn, 0x02);
                if (vid == CIRRUS_VENDOR_ID && did == CIRRUS_DEVICE_ID) {
                    *out_bus = bus; *out_dev = dev; *out_fn = fn;
                    return 1;
                }
            }
        }
    }
    return 0;
}

static uint64_t clgd_map_lfb(uint8_t bus, uint8_t dev, uint8_t fn)
{
    uint32_t bar0 = pci_read32_raw(bus, dev, fn, 0x10);
    uint32_t bar1 = pci_read32_raw(bus, dev, fn, 0x14);
    uint32_t bar2 = pci_read32_raw(bus, dev, fn, 0x18);
    uint32_t bar3 = pci_read32_raw(bus, dev, fn, 0x1C);
    uint32_t bar4 = pci_read32_raw(bus, dev, fn, 0x20);
    uint32_t bar5 = pci_read32_raw(bus, dev, fn, 0x24);
    (void)bar2; (void)bar3; (void)bar4; (void)bar5;

    uint64_t lfb = 0;
    if (bar_is_mem(bar1)) {
        uint32_t bar1_hi = 0;
        if (((bar1 >> 1) & 0x3u) == 0x2u)
            bar1_hi = pci_read32_raw(bus, dev, fn, 0x18);
        lfb = bar_addr(bar1, bar1_hi);
    } else if (bar_is_mem(bar0)) {
        uint32_t bar0_hi = 0;
        if (((bar0 >> 1) & 0x3u) == 0x2u)
            bar0_hi = pci_read32_raw(bus, dev, fn, 0x14);
        lfb = bar_addr(bar0, bar0_hi);
    }

    if (lfb) {
        uint64_t fb_base = lfb & ~0xFFFFFULL; // 1MB align down
        uint64_t map_size = 4ULL * 1024ULL * 1024ULL;
        paging_map_range(fb_base, fb_base, map_size, 0x001 | 0x002);
        klog_printf("cirrus: LFB @0x%llx mapped size=0x%llx\n", (unsigned long long)fb_base, (unsigned long long)map_size);
    }
    return lfb;
}

static void clgd_try_adopt_existing_mode(uint64_t lfb)
{
    if (vbe_is_initialized()) {
        klog_printf("cirrus: using existing framebuffer %ux%u bpp=%u pitch=%u at 0x%llx\n",
            vbe_get_width(), vbe_get_height(), vbe_get_bpp(), vbe_get_pitch(),
            (unsigned long long)vbe_get_addr());
        qemu_log_printf("cirrus: using existing framebuffer %ux%u bpp=%u pitch=%u at 0x%llx\n",
            vbe_get_width(), vbe_get_height(), vbe_get_bpp(), vbe_get_pitch(),
            (unsigned long long)vbe_get_addr());
        return;
    }
    if (lfb) {
        uint32_t w = 1024, h = 768, bpp = 32;
        uint32_t pitch = w * 4;
        vbe_init(lfb, w, h, pitch, bpp);
        klog_printf("cirrus: VBE adopted as generic LFB %ux%u@%u\n", w, h, bpp);
        qemu_log_printf("cirrus: VBE adopted as generic LFB %ux%u@%u\n", w, h, bpp);
    }
}

// ---------------- Modeset (best-effort) ----------------
static uint64_t g_cirrus_lfb = 0;

// ----------- VGA register port helpers -----------
static inline void vga_out(uint16_t port, uint8_t idx, uint8_t val){ outb(port, idx); outb(port+1, val);} // GEN/SEQ/GC/CRTC
static inline void vga_attr_out(uint8_t idx, uint8_t val){ inb(0x3DA); outb(0x3C0, idx); outb(0x3C0, val);} // ATTR

struct ModeRegs{
    const uint8_t seq[5];
    const uint8_t crtc[25];
    const uint8_t gc[9];
    const uint8_t attr[21];
    uint8_t misc;
    uint8_t ext_seq_b7; // enable 8/16/24/32 bpp
};

static const ModeRegs mode_640x480_32 = {
    {0x03,0x01,0x0F,0x00,0x0E},
    {0x5F,0x4F,0x50,0x82,0x54,0x80,0x0B,0x3E,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0xEA,0x8C,0xDF,0x50,0x00,0xE7,0x04,0xE3,0xFF,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x40,0x05,0x0F,0xFF},
    {0x00,0x01,0x02,0x03,0x04,0x05,0x14,0x07,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x01,0x00,0x0F,0x00,0x00},
    0xE3,
    0x0C
};
static const ModeRegs mode_800x600_32 = {/* trimmed for brevity same pattern*/ {0x03,0x01,0x0F,0x00,0x06},
    {0x7D,0x63,0x64,0x9E,0x69,0x92,0x6F,0xF0,0x00,0x6C,0x00,0x00,0x00,0x00,0x00,0xEA,0x8C,0xFF,0x6C,0x00,0xE7,0x04,0xE3,0xFF,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x40,0x05,0x0F,0xFF},
    {0x00,0x01,0x02,0x03,0x04,0x05,0x14,0x07,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x01,0x00,0x0F,0x00,0x00},
    0xEB,
    0x0C};
// Additional modes omitted

static const ModeRegs* pick_mode(uint32_t w,uint32_t h){
    if(w==640&&h==480) return &mode_640x480_32;
    if(w==800&&h==600) return &mode_800x600_32;
    return nullptr;}

static void write_mode_regs(const ModeRegs* m){
    // disable display
    uint8_t misc = m->misc; outb(0x3C2,misc);
    // SEQ
    for(int i=0;i<5;i++) vga_out(0x3C4,i,m->seq[i]);
    // unlock CRTC
    vga_out(0x3D4,0x11, m->crtc[0x11]&0x7F);
    for(int i=0;i<25;i++) vga_out(0x3D4,i,m->crtc[i]);
    // GC
    for(int i=0;i<9;i++) vga_out(0x3CE,i,m->gc[i]);
    // ATTR
    for(int i=0;i<21;i++) vga_attr_out(i,m->attr[i]);
    // Extended SEQ B7 (pixel format)
    vga_out(0x3C4,0x07,m->ext_seq_b7);
    // re-enable
    vga_out(0x3C4,0x01,0x01);
    // Unblank display (bit 5 of Attribute Controller index 0x12)
    inb(0x3DA);
    outb(0x3C0,0x20);
}

static int clgd_hw_set_mode(uint32_t w, uint32_t h, uint32_t bpp)
{
    if (bpp != 32) return -22;
    if (vbe_is_initialized() && vbe_get_width() == w && vbe_get_height() == h && vbe_get_bpp() == bpp)
        return 0;

    // Force Bochs VBE DISPI modeset (reliable in QEMU with cirrus/std)
    const uint16_t IO_INDEX = 0x1CE;
    const uint16_t IO_DATA  = 0x1CF;
    const uint16_t IDX_ID      = 0x0000;
    const uint16_t IDX_XRES    = 0x0001;
    const uint16_t IDX_YRES    = 0x0002;
    const uint16_t IDX_BPP     = 0x0003;
    const uint16_t IDX_ENABLE  = 0x0004;
    const uint16_t DISPI_ID0   = 0xB0C4;
    const uint16_t EN_ENABLED  = 0x0001;
    const uint16_t EN_LFB      = 0x0040;
    auto vbe_w = [&](uint16_t idx, uint16_t val){ outw(IO_INDEX, idx); outw(IO_DATA, val); };
    auto vbe_r = [&](uint16_t idx)->uint16_t{ outw(IO_INDEX, idx); return inw(IO_DATA); };

    uint16_t id = vbe_r(IDX_ID);
    if (id != DISPI_ID0) {
        klog_printf("clgd: dispi not present, cannot set mode\n");
        return -38;
    }

    vbe_w(IDX_ENABLE, 0);
    vbe_w(IDX_XRES, (uint16_t)w);
    vbe_w(IDX_YRES, (uint16_t)h);
    vbe_w(IDX_BPP,  32);
    vbe_w(IDX_ENABLE, (uint16_t)(EN_ENABLED | EN_LFB));

    // Prefer hardware-reported pitch from CRTC[0x13] (bytes/scanline = val<<3)
    outb(0x3D4, 0x13);
    uint32_t pitch = (uint32_t)inb(0x3D5) << 3;
    if (!pitch || pitch < w * 4) pitch = w * 4; // safe fallback
    klog_printf("clgd: pitch=%u (crtc13)", pitch);

    // Map framebuffer range and init VBE layer
    uint64_t fb_base = g_cirrus_lfb & ~0xFFFFFULL;
    paging_map_range(fb_base, fb_base, 4ULL * 1024ULL * 1024ULL, PAGE_PRESENT | PAGE_WRITABLE);

    // Unblank display
    inb(0x3DA);
    outb(0x3C0, 0x20);

    // Write simple test pattern to confirm visibility
    volatile uint8_t* fb8 = (volatile uint8_t*)(uintptr_t)g_cirrus_lfb;
    if (fb8) {
        for (uint32_t y = 0; y < (h < 64 ? h : 64); ++y) {
            uint32_t ofs = y * pitch;
            for (uint32_t x = 0; x < w; ++x) {
                uint32_t p = (x * 1315423911u) ^ (y * 2654435761u);
                fb8[ofs + x*4 + 0] = (uint8_t)p;
                fb8[ofs + x*4 + 1] = (uint8_t)(p >> 8);
                fb8[ofs + x*4 + 2] = (uint8_t)(p >> 16);
                fb8[ofs + x*4 + 3] = 0x00;
            }
        }
    }

    vbe_init(g_cirrus_lfb, w, h, pitch, 32);
    vbec_init_console();
    vbe_set_present_enabled(1);
    klog_printf("clgd: fb reinit(dispi) %ux%u pitch=%u base=0x%llx\n", w, h, pitch, (unsigned long long)g_cirrus_lfb);
    return 0;
}

extern "C" int clgd54xx_set_mode(unsigned int width, unsigned int height, unsigned int bpp)
{
    if (!g_cirrus_lfb) return -19; // ENODEV
    if (!(bpp == 32 || bpp == 24 || bpp == 16)) return -22; // EINVAL
    int rc = clgd_hw_set_mode(width, height, bpp);
    if (rc != 0) return rc;
    uint32_t pitch = (bpp == 32) ? (width * 4u) : (bpp == 24) ? (width * 3u) : (width * 2u);
    vbe_init(g_cirrus_lfb, width, height, pitch, bpp);
    vbec_init_console();
    klog_printf("cirrus: VBE console reinit %ux%u@%u pitch=%u\n", width, height, bpp, pitch);
    return 0;
}

extern "C" int clgd54xx_set_best_mode(void)
{
    struct Mode { uint32_t w,h,bpp; } modes[] = {
        {1920,1080,32}, {1600,1200,32}, {1366,768,32}, {1280,1024,32}, {1280,800,32},
        {1152,864,32}, {1024,768,32}, {800,600,32}, {640,480,32},
        {1280,1024,24}, {1024,768,24}, {800,600,24}, {640,480,24},
        {1280,1024,16}, {1024,768,16}, {800,600,16}, {640,480,16},
        {1024,768,8}, {800,600,8}, {640,480,8}
    };
    for (unsigned i = 0; i < sizeof(modes)/sizeof(modes[0]); ++i) {
        if (vbe_is_initialized() && vbe_get_width()==modes[i].w && vbe_get_height()==modes[i].h && vbe_get_bpp()==modes[i].bpp)
            return 0;
        int rc = clgd54xx_set_mode(modes[i].w, modes[i].h, modes[i].bpp);
        if (rc == 0) return 0;
    }
    return -38;
}

extern "C" void clgd54xx_init(void)
{
    uint8_t bus = 0, dev = 0, fn = 0;
    if (!clgd_find(&bus, &dev, &fn)) {
        klog_printf("cirrus: device not found\n");
        return;
    }

    clgd_print_device(bus, dev, fn);

    uint16_t cmd = pci_read16_raw(bus, dev, fn, 0x04);
    cmd |= 0x0002;
    cmd |= 0x0004;
    uint32_t cfg = pci_read32_raw(bus, dev, fn, 0x04 & 0xFC);
    uint32_t shift = ((0x04 & 2) * 8);
    cfg &= ~(0xFFFFu << shift);
    cfg |= ((uint32_t)cmd) << shift;
    pci_write32_raw(bus, dev, fn, 0x04 & 0xFC, cfg);

    g_cirrus_lfb = clgd_map_lfb(bus, dev, fn);
    if (!g_cirrus_lfb) klog_printf("cirrus: no LFB BAR detected\n");

    clgd_try_adopt_existing_mode(g_cirrus_lfb);
    (void)clgd54xx_set_best_mode();

    klog_printf("cirrus: preferred modes: 1280x1024, 1024x768, 800x600, 640x480 (32bpp)\n");
}


