#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>

// Page table entry flags
#define PAGE_PRESENT        0x001
#define PAGE_WRITABLE       0x002
#define PAGE_USER           0x004
#define PAGE_WRITETHROUGH   0x008
#define PAGE_CACHE_DISABLE  0x010
#define PAGE_ACCESSED       0x020
#define PAGE_DIRTY          0x040
#define PAGE_HUGE           0x080
#define PAGE_GLOBAL         0x100
#define PAGE_NX             0x8000000000000000ULL

// Page table levels
#define PAGE_SIZE           0x1000
#define PAGE_MASK           0x000FFFFFFFFFF000ULL

// Virtual address structure (deprecated bitfields)
typedef struct {
    uint64_t offset : 12;
    uint64_t l1_index : 9;
    uint64_t l2_index : 9;
    uint64_t l3_index : 9;
    uint64_t l4_index : 9;
    uint64_t sign_extend : 16;
} __attribute__((packed)) virtual_address_t;

// Page table entry
typedef uint64_t page_table_entry_t;

// Page table
typedef page_table_entry_t page_table_t[512];

// Paging functions
void paging_init();
void paging_map_page(uint64_t virtual_addr, uint64_t physical_addr, uint64_t flags);
void paging_unmap_page(uint64_t virtual_addr);
void paging_map_range(uint64_t virtual_start, uint64_t physical_start, uint64_t size, uint64_t flags);
void paging_load_cr3(uint64_t cr3);
uint64_t paging_get_cr3();

// Current page directory
extern page_table_t* current_page_directory;

#endif // PAGING_H 