#include <pit.h>
#include <debug.h>
#include <pic.h>
#include <idt.h>
#include <vbedbuff.h>
#include <vbetty.h>
#include <thread.h>

// Global variables
volatile uint64_t pit_ticks = 0;
volatile uint32_t pit_frequency = 1000; // Default 100 Hz

// PIT handler - called on IRQ 0
void pit_handler(cpu_registers_t* regs) {
    pit_ticks++;
    

    if (pit_ticks % (pit_frequency / 50) == 0) { // More frequent updates for better responsiveness
        if (vbedbuff_is_initialized()) {
            vbedbuff_swap();
        }
    }

    // Убираем обновление курсора из таймера - курсор должен гореть постоянно
    // if (pit_ticks % 250 == 0) {
    //     if (vbedbuff_is_initialized()) {
    //         vbetty_update_cursor();
    //     }
    // }
    
    // Вызываем планировщик реже - каждые 10 тиков (10 мс при 1000 Гц)
    if (init && (pit_ticks % 10 == 0)) {
        thread_schedule();
    }
    
    // EOI отправляется в isr_dispatch
}

// Initialize PIT with default frequency (100 Hz)
void pit_init() {
    PrintfQEMU("Initializing PIT timer...\n");
    
    // Set default frequency (1000 Hz)
    pit_set_frequency(1000);
    PrintfQEMU("DEBUG: pit_frequency = %u\n", pit_frequency);
    // Set up PIT handler for IRQ 0
    idt_set_handler(32, pit_handler); // IRQ 0 = vector 32
    
    
    PrintfQEMU("PIT initialized at %u Hz\n", pit_frequency);
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
    
    PrintfQEMU("PIT frequency set to %u Hz (divisor: %u)\n", pit_frequency, divisor);
}

// Set PIT divisor directly
void pit_set_divisor(uint16_t divisor) {
    // Send command byte
    outb(PIT_COMMAND, PIT_CMD_CHANNEL0 | PIT_CMD_ACCESS_BOTH | PIT_CMD_MODE3 | PIT_CMD_BINARY);
    
    // Send divisor (low byte first, then high byte)
    outb(PIT_CHANNEL0, divisor & 0xFF);
    outb(PIT_CHANNEL0, (divisor >> 8) & 0xFF);
}

// Get current PIT count
uint16_t pit_get_current_count() {
    // Send command to latch current count
    outb(PIT_COMMAND, PIT_CMD_CHANNEL0 | PIT_CMD_ACCESS_BOTH);
    
    // Read count (low byte first, then high byte)
    uint16_t count = inb(PIT_CHANNEL0);
    count |= (uint16_t)inb(PIT_CHANNEL0) << 8;
    
    return count;
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