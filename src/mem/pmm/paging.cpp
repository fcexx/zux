#include "paging.h"
#include "debug.h"

// Page tables
static page_table_t page_table_l4 __attribute__((aligned(4096)));
static page_table_t page_table_l3 __attribute__((aligned(4096)));
static page_table_t page_table_l2 __attribute__((aligned(4096)));
static page_table_t page_table_l1 __attribute__((aligned(4096)));

// Additional page tables for framebuffer
static page_table_t page_table_l3_fb __attribute__((aligned(4096)));
static page_table_t page_table_l2_fb __attribute__((aligned(4096)));
static page_table_t page_table_l1_fb __attribute__((aligned(4096)));

// Current page directory
page_table_t* current_page_directory = &page_table_l4;

// Clear page table
static void clear_page_table(page_table_t* table) {
    for (int i = 0; i < 512; i++) {
        (*table)[i] = 0;
    }
}

// Get page table entry
static page_table_entry_t* get_page_table_entry(uint64_t virtual_addr, bool create) {
    virtual_address_t* addr = (virtual_address_t*)&virtual_addr;
    
    // Check if L4 entry exists
    if (!(page_table_l4[addr->l4_index] & PAGE_PRESENT)) {
        if (!create) return nullptr;
        
        // Allocate new L3 page table
        page_table_t* new_l3 = nullptr;
        if (addr->l4_index == 0) {
            new_l3 = &page_table_l3;
        } else if (addr->l4_index == 0x1F0) { // 0xfd000000 >> 39
            new_l3 = &page_table_l3_fb;
        } else {
            PrintQEMU("No L3 table for L4 index: ");
            PrintfQEMU("0x%x\n", addr->l4_index);
            return nullptr;
        }
        
        clear_page_table(new_l3);
        page_table_l4[addr->l4_index] = (uint64_t)new_l3 | PAGE_PRESENT | PAGE_WRITABLE;
    }
    
    // Get L3 table
    page_table_entry_t* l3_table = (page_table_entry_t*)(page_table_l4[addr->l4_index] & PAGE_MASK);
    
    // Check if L3 entry exists
    if (!(l3_table[addr->l3_index] & PAGE_PRESENT)) {
        if (!create) return nullptr;
        
        // Allocate new L2 page table
        page_table_t* new_l2 = nullptr;
        if (addr->l4_index == 0 && addr->l3_index == 0) {
            new_l2 = &page_table_l2;
        } else if (addr->l4_index == 0x1F0 && addr->l3_index == 0) { // 0xfd000000 >> 30 = 0
            new_l2 = &page_table_l2_fb;
        } else {
            PrintQEMU("No L2 table for L3 index: ");
            PrintfQEMU("0x%x\n", addr->l3_index);
            return nullptr;
        }
        
        clear_page_table(new_l2);
        l3_table[addr->l3_index] = (uint64_t)new_l2 | PAGE_PRESENT | PAGE_WRITABLE;
    }
    
    // Get L2 table
    page_table_entry_t* l2_table = (page_table_entry_t*)(l3_table[addr->l3_index] & PAGE_MASK);
    
    // Check if L2 entry exists
    if (!(l2_table[addr->l2_index] & PAGE_PRESENT)) {
        if (!create) return nullptr;
        
        // Allocate new L1 page table
        page_table_t* new_l1 = nullptr;
        if (addr->l4_index == 0 && addr->l3_index == 0 && addr->l2_index == 0) {
            new_l1 = &page_table_l1;
        } else if (addr->l4_index == 0x1F0 && addr->l3_index == 0 && addr->l2_index == 0) {
            new_l1 = &page_table_l1_fb;
        } else {
            PrintQEMU("No L1 table for L2 index: ");
            PrintfQEMU("0x%x\n", addr->l2_index);
            return nullptr;
        }
        
        clear_page_table(new_l1);
        l2_table[addr->l2_index] = (uint64_t)new_l1 | PAGE_PRESENT | PAGE_WRITABLE;
    }
    
    // Get L1 table
    page_table_entry_t* l1_table = (page_table_entry_t*)(l2_table[addr->l2_index] & PAGE_MASK);
    
    // Return L1 entry
    return &l1_table[addr->l1_index];
}

void paging_init() {
    PrintQEMU("Initializing paging...\n");
    
    // Clear all page tables
    clear_page_table(&page_table_l4);
    clear_page_table(&page_table_l3);
    clear_page_table(&page_table_l2);
    clear_page_table(&page_table_l1);
    clear_page_table(&page_table_l3_fb);
    clear_page_table(&page_table_l2_fb);
    clear_page_table(&page_table_l1_fb);
    
    // Identity map first 2MB
    paging_map_range(0x00000000, 0x00000000, 0x200000, PAGE_PRESENT | PAGE_WRITABLE);
    
    // Map framebuffer at 0xfd000000
    paging_map_range(0xfd000000, 0xfd000000, 0x1000000, PAGE_PRESENT | PAGE_WRITABLE);
    
    // Load page table
    paging_load_cr3((uint64_t)&page_table_l4);
    
    PrintQEMU("Paging initialized\n");
}

void paging_map_page(uint64_t virtual_addr, uint64_t physical_addr, uint64_t flags) {
    page_table_entry_t* entry = get_page_table_entry(virtual_addr, true);
    if (entry) {
        *entry = (physical_addr & PAGE_MASK) | flags;
        
        // Invalidate TLB
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
        
        // Invalidate TLB
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