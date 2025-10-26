#include <paging.h>
#include <debug.h>
#include <vbe.h>
#include <stdint.h>

// minimal size_t for freestanding
typedef unsigned long long size_t;

// Top-level L4 table
static page_table_t page_table_l4 __attribute__((aligned(4096)));

// Simple internal pool for page-table allocations (no heap needed)
static uint8_t pt_pool[512 * 1024] __attribute__((aligned(4096))); // 512KB → 128 tables
static size_t pt_pool_offset = 0;

static inline page_table_t* alloc_page_table_from_pool() {
        if (pt_pool_offset + 4096 > sizeof(pt_pool)) {
                PrintQEMU("[paging] PT pool exhausted\n");
                return nullptr;
        }
        page_table_t* t = reinterpret_cast<page_table_t*>(pt_pool + pt_pool_offset);
        pt_pool_offset += 4096;
        // clear
        for (int i = 0; i < 512; ++i) {
                (*t)[i] = 0;
        }
        return t;
}

// Current page directory
page_table_t* current_page_directory = &page_table_l4;

// Clear page table
static void clear_page_table(page_table_t* table) {
        for (int i = 0; i < 512; i++) {
                (*table)[i] = 0;
        }
}

// Get page table entry for 4KiB page
static page_table_entry_t* get_page_table_entry(uint64_t virtual_addr, bool create) {
        virtual_address_t* addr = (virtual_address_t*)&virtual_addr;
        
        // L4 (we expect low-half, l4_index==0 for 32-bit addresses)
        if (!(page_table_l4[addr->l4_index] & PAGE_PRESENT)) {
                if (!create) return nullptr;
                page_table_t* new_l3 = alloc_page_table_from_pool();
                if (!new_l3) return nullptr;
                page_table_l4[addr->l4_index] = ((uint64_t)new_l3) | PAGE_PRESENT | PAGE_WRITABLE;
        }
        page_table_entry_t* l3_table = (page_table_entry_t*)(page_table_l4[addr->l4_index] & PAGE_MASK);
        
        // L3
        if (!(l3_table[addr->l3_index] & PAGE_PRESENT)) {
                if (!create) return nullptr;
                page_table_t* new_l2 = alloc_page_table_from_pool();
                if (!new_l2) return nullptr;
                l3_table[addr->l3_index] = ((uint64_t)new_l2) | PAGE_PRESENT | PAGE_WRITABLE;
        }
        page_table_entry_t* l2_table = (page_table_entry_t*)(l3_table[addr->l3_index] & PAGE_MASK);
        
        // L2
        if (!(l2_table[addr->l2_index] & PAGE_PRESENT)) {
                if (!create) return nullptr;
                page_table_t* new_l1 = alloc_page_table_from_pool();
                if (!new_l1) return nullptr;
                l2_table[addr->l2_index] = ((uint64_t)new_l1) | PAGE_PRESENT | PAGE_WRITABLE;
        }
        page_table_entry_t* l1_table = (page_table_entry_t*)(l2_table[addr->l2_index] & PAGE_MASK);
        
        // L1 entry
        return &l1_table[addr->l1_index];
}

// Ensure USER bit is set on all parent entries for the given VA
static void ensure_user_parent_entries(uint64_t virtual_addr) {
        virtual_address_t* addr = (virtual_address_t*)&virtual_addr;
        if (!(page_table_l4[addr->l4_index] & PAGE_PRESENT)) return;
        page_table_entry_t* l3_table = (page_table_entry_t*)(page_table_l4[addr->l4_index] & PAGE_MASK);
        // set U on L4->L3 entry (not applicable on x86_64, bit is in entry)
        page_table_l4[addr->l4_index] |= PAGE_USER;
        if (!(l3_table[addr->l3_index] & PAGE_PRESENT)) return;
        l3_table[addr->l3_index] |= PAGE_USER;
        page_table_entry_t* l2_table = (page_table_entry_t*)(l3_table[addr->l3_index] & PAGE_MASK);
        if (!(l2_table[addr->l2_index] & PAGE_PRESENT)) return;
        l2_table[addr->l2_index] |= PAGE_USER;
}

void paging_init() {
        PrintQEMU("Initializing paging...\n");
        
        // Clear L4 and reset pool
        clear_page_table(&page_table_l4);
        pt_pool_offset = 0;
        
        // Identity map first 64MB as user-accessible (debug aid to avoid PF from userland touching low memory)
        // NOTE: keep until user-mode has no dependency on low identity addresses
        paging_map_range(0x00000000ULL, 0x00000000ULL, 0x04000000ULL, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
        
        // Map linear framebuffer only if VBE console is initialized
        if (vbe_is_initialized()) {
                uint64_t fb_addr = vbe_get_addr();
                uint32_t fb_pitch = vbe_get_pitch();
                uint32_t fb_height = vbe_get_height();
                uint32_t fb_bpp = vbe_get_bpp();
                if (fb_addr && fb_pitch && fb_height && (fb_bpp==16 || fb_bpp==24 || fb_bpp==32)) {
                uint64_t fb_size = (uint64_t)fb_pitch * (uint64_t)fb_height;
                // округлим до ближайшего мегабайта вверх, ограничим 64MB
                if (fb_size < 0x00100000ULL) fb_size = 0x00100000ULL;
                if (fb_size > 0x04000000ULL) fb_size = 0x04000000ULL;
                uint64_t fb_base = fb_addr & ~0xFFFFFULL; // выровняем вниз по 1MB
                uint64_t map_size = (fb_size + 0xFFFFFULL) & ~0xFFFFFULL;
                paging_map_range(fb_base, fb_base, map_size, PAGE_PRESENT | PAGE_WRITABLE);
                qemu_log_printf("[paging] mapped framebuffer at 0x%llx size=0x%llx\n", (unsigned long long)fb_base, (unsigned long long)map_size);
                }
        }

        // Map SMBIOS table if present (for UEFI)
        extern uint64_t g_smbios_addr; extern uint32_t g_smbios_len;
        if (g_smbios_addr && g_smbios_len) {
                uint64_t base = g_smbios_addr & ~0xFFFULL;
                uint64_t sz = ((g_smbios_addr + g_smbios_len) - base + 0xFFFULL) & ~0xFFFULL;
                paging_map_range(base, base, sz, PAGE_PRESENT);
                qemu_log_printf("[paging] mapped SMBIOS at 0x%llx size=0x%llx\n",
                        (unsigned long long)base, (unsigned long long)sz);
        }
        
        // Load CR3
        paging_load_cr3((uint64_t)&page_table_l4);
        
        PrintQEMU("Paging initialized\n");
}

void paging_map_page(uint64_t virtual_addr, uint64_t physical_addr, uint64_t flags) {
        page_table_entry_t* entry = get_page_table_entry(virtual_addr, true);
        if (entry) {
                if (flags & PAGE_USER) {
                        ensure_user_parent_entries(virtual_addr);
                }
                *entry = (physical_addr & PAGE_MASK) | flags;
                asm volatile("invlpg (%0)" : : "r" (virtual_addr) : "memory");
        } else {
                PrintQEMU("Failed to map page: ");
                qemu_log_printf("0x%x -> 0x%x\n", virtual_addr, physical_addr);
        }
}

void paging_unmap_page(uint64_t virtual_addr) {
        page_table_entry_t* entry = get_page_table_entry(virtual_addr, false);
        if (entry) {
                *entry = 0;
                asm volatile("invlpg (%0)" : : "r" (virtual_addr) : "memory");
        }
}

void paging_map_range(uint64_t virtual_start, uint64_t physical_start, uint64_t size, uint64_t flags) {
        for (uint64_t i = 0; i < size; i += PAGE_SIZE) {
                paging_map_page(virtual_start + i, physical_start + i, flags);
        }
}

void paging_load_cr3(uint64_t cr3) {
        asm volatile("mov %0, %%cr3" : : "r" (cr3) : "memory");
}

uint64_t paging_get_cr3() {
        uint64_t cr3;
        asm volatile("mov %%cr3, %0" : "=r" (cr3));
        return cr3;
} 