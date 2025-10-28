#include <pic.h>
#include <debug.h>

static void (*irq_handlers[16])() = {nullptr};

void pic_init() {
        // Сохраняли значения IMR в a1/a2, но не использовали — уберём предупреждение
        uint8_t a1 = inb(0x21);
        uint8_t a2 = inb(0xA1);
        (void)a1; (void)a2;
        
        outb(0x20, 0x11);
        outb(0xA0, 0x11);
        outb(0x21, 0x20);
        outb(0xA1, 0x28);
        outb(0x21, 0x04);
        outb(0xA1, 0x02);
        outb(0x21, 0x01);
        outb(0xA1, 0x01);
        outb(0x21, 0x00);
        outb(0xA1, 0x00);
}

void pic_send_eoi(uint8_t irq) {
        if (irq >= 8) {
                outb(0xA0, 0x20);
        }
        outb(0x20, 0x20);
}

void pic_mask_irq(uint8_t irq) {
        uint16_t port;
        uint8_t value;
        
        if (irq < 8) {
                port = 0x21;
        } else {
                port = 0xA1;
                irq -= 8;
        }
        
        value = inb(port) | (1 << irq);
        outb(port, value);
}

void pic_unmask_irq(uint8_t irq) {
        uint16_t port;
        uint8_t value;
        
        if (irq < 8) {
                port = 0x21;
        } else {
                port = 0xA1;
                irq -= 8;
        }
        
        value = inb(port) & ~(1 << irq);
        outb(port, value);
}

void pic_set_irq_handler(uint8_t irq, void (*handler)()) {
        irq_handlers[irq] = handler;
}
