#include <pit.h>
#include <debug.h> 
#include <pic.h>
#include <idt.h>
// VGA text mode uses hardware cursor; no backbuffer swap needed
#include <thread.h>
#include <vbe.h>
#include <vbetty.h>

// Global variables
volatile uint64_t pit_ticks = 0;
volatile uint32_t pit_frequency = 1000; // Default 100 Hz

// PIT handler - called on IRQ 0
void pit_handler(cpu_registers_t* regs) {
        pit_ticks++;
        (void)regs;
        
        // Вызываем планировщик реже - каждые 10 тиков (10 мс при 1000 Гц)
        if (init && (pit_ticks % 10 == 0)) {
                thread_schedule();
        }
    if (vbe_console_ready()) {
                // Выполняем показ экрана только из таймера
                vbe_cursor_tick();
                if (pit_ticks % 50 == 0) vbe_swap();
        }
        
        // EOI отправляется в isr_dispatch
}

// Initialize PIT with default frequency (100 Hz)
void pit_init() {
        
        // Set default frequency (1000 Hz)
        int freq = 1000;
        pit_set_frequency(freq);
#ifdef K_QEMU_SERIAL_LOG
        qemu_log_printf("DEBUG: pit_frequency = %u\n", pit_frequency);
#endif
        // Set up PIT handler for IRQ 0
        idt_set_handler(32, pit_handler); // IRQ 0 = vector 32
        
        
#ifdef K_QEMU_SERIAL_LOG
        qemu_log_printf("PIT initialized at %u Hz\n", pit_frequency);
#endif
}

// Set PIT frequency in Hz
void pit_set_frequency(uint32_t frequency) {
        if (frequency == 0) return;
        
        // Calculate divisor
        uint32_t divisor = PIT_FREQUENCY / frequency;
        
        // Ensure divisor is in valid range (1-65535)
        if (divisor < 1) divisor = 1;
        if (divisor > 65535) divisor = 65535;
        
        // Recalculate actual frequency
        pit_frequency = PIT_FREQUENCY / divisor;
        
        // Set the divisor
        pit_set_divisor((uint16_t)divisor);
        
#ifdef K_QEMU_SERIAL_LOG
        qemu_log_printf("PIT frequency set to %u Hz (divisor: %u)\n", pit_frequency, divisor);
#endif
}

// Set PIT divisor directly
void pit_set_divisor(uint16_t divisor) {
        // Send command byte
        // Use MODE2 (rate generator) to have linear down-counting, which simplifies
        // reading the current counter value for time interpolation
        outb(PIT_COMMAND, PIT_CMD_CHANNEL0 | PIT_CMD_ACCESS_BOTH | PIT_CMD_MODE2 | PIT_CMD_BINARY);
        
        // Send divisor (low byte first, then high byte)
        outb(PIT_CHANNEL0, divisor & 0xFF);
        outb(PIT_CHANNEL0, (divisor >> 8) & 0xFF);
}

// Get current PIT count
uint16_t pit_get_current_count() {
        // Latch current count (counter latch command: channel0 + access=00)
        outb(PIT_COMMAND, PIT_CMD_CHANNEL0);
        // Read latched count (low then high)
        uint16_t lo = inb(PIT_CHANNEL0);
        uint16_t hi = inb(PIT_CHANNEL0);
        return (uint16_t)((hi << 8) | lo);
}

// Sleep for specified number of milliseconds
void pit_sleep_ms(uint32_t milliseconds) {
        uint64_t target_ticks = pit_ticks + (milliseconds * pit_frequency / 1000);
        
        while (pit_ticks < target_ticks) {
                // Wait for next tick
                asm volatile("hlt");
        }
}

// Get current tick count
uint64_t pit_get_ticks() {
        return pit_ticks;
}

// Get time in milliseconds since boot
uint64_t pit_get_time_ms() {
        return (pit_ticks * 1000) / pit_frequency;
}

uint64_t pit_get_frequency() {
        return pit_frequency;
}