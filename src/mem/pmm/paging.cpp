#include <paging.h>
#include <debug.h>
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

    // Identity map first 64MB
    paging_map_range(0x00000000ULL, 0x00000000ULL, 0x04000000ULL, PAGE_PRESENT | PAGE_WRITABLE);

    // Map a 16MB window where typical linear framebuffer lies (0xFD000000)
    paging_map_range(0xFD000000ULL, 0xFD000000ULL, 0x01000000ULL, PAGE_PRESENT | PAGE_WRITABLE);

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
        PrintfQEMU("0x%x -> 0x%x\n", virtual_addr, physical_addr);
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