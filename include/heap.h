#ifndef HEAP_H
#define HEAP_H

#include <stdint.h>
#include <stddef.h>

// Heap block header structure - optimized for x86_64 cache line alignment
struct __attribute__((aligned(64))) heap_block_header {
    uint64_t size : 63;        // Block size (excluding header)
    uint64_t is_free : 1;      // Free flag (1 = free, 0 = allocated)
    uint64_t magic;            // Magic number for corruption detection
    heap_block_header* next;   // Next block in list
    heap_block_header* prev;   // Previous block in list
};

// Heap statistics structure
struct heap_stats {
    uint64_t total_allocated;
    uint64_t total_freed;
    uint64_t current_used;
    uint64_t peak_used;
    uint64_t fragmentation;
    uint64_t block_count;
};

// Memory pool for small allocations (16-512 bytes)
struct __attribute__((aligned(64))) memory_pool {
    static constexpr size_t POOL_SIZE = 4096;  // 4KB per pool
    static constexpr size_t MAX_SMALL_SIZE = 512;
    static constexpr size_t NUM_SIZES = 9;     // 16, 32, 64, 128, 256, 512 bytes
    
    uint8_t* data;
    uint64_t bitmap[NUM_SIZES][POOL_SIZE / 64];  // Bitmap for each size class
    memory_pool* next;
    
    memory_pool();
};

// Heap allocator class - optimized for x86_64
class __attribute__((aligned(64))) HeapAllocator {
public:
    // Free list buckets for different size classes (power of 2)
    static constexpr size_t NUM_BUCKETS = 32;
    static constexpr size_t MIN_BLOCK_SIZE = 16;
    static constexpr size_t MAX_BLOCK_SIZE = 1ULL << 31; // 2GB
    
    heap_block_header* free_lists[NUM_BUCKETS];
    heap_block_header* heap_start;
    heap_block_header* heap_end;
    // Raw heap memory span (start inclusive, end exclusive)
    uint8_t* heap_mem_start;
    uint8_t* heap_mem_end;
    
    // Memory pools for small allocations
    memory_pool* memory_pools;
    
    heap_stats stats;
    
    // Magic number for corruption detection
    static constexpr uint64_t MAGIC_NUMBER = 0xDEADBEEFCAFEBABE;
    
    // Optimized size class calculation using bit manipulation
    static inline size_t get_bucket_index(size_t size) {
        if (size < MIN_BLOCK_SIZE) size = MIN_BLOCK_SIZE;
        // compute floor(log2(size-1)) in a defined way
        unsigned long long x = static_cast<unsigned long long>(size - 1);
        const size_t bits = sizeof(unsigned long long) * 8;
        size_t leading = __builtin_clzll(x);
        return (bits - 1) - leading;
    }
    
    // Merge adjacent free blocks
    void merge_blocks(heap_block_header* block);
    
    // Split large block if needed
    heap_block_header* split_block(heap_block_header* block, size_t requested_size);
    
    // Add block to appropriate free list
    void add_to_free_list(heap_block_header* block);
    
    // Remove block from free list
    void remove_from_free_list(heap_block_header* block);
    
    // Validate block integrity
    bool validate_block(const heap_block_header* block) const;
    
    // Find best fit block in free list
    heap_block_header* find_best_fit(size_t size);
    
    // Expand heap by requesting more memory from physical memory manager
    bool expand_heap(size_t additional_size);

public:
    // Constructor - initialize heap with given memory region
    HeapAllocator(void* start_addr, size_t initial_size);
    
    // Destructor
    ~HeapAllocator() = default;
    
    // Core allocation functions
    void* malloc(size_t size);
    void* malloc_aligned(size_t size, size_t alignment);
    void mfree(void* ptr);
    void* realloc(void* ptr, size_t new_size);
    
    // Utility functions
    size_t get_block_size(void* ptr) const;
    bool is_valid_pointer(void* ptr) const;
    void get_stats(heap_stats* stats_out) const;
    void dump_heap_info() const;
    
    // Memory pool functions for small allocations
    void* allocate_small(size_t size);
    void deallocate_small(void* ptr);
    
    // Defragmentation
    void defragment();
    
    // Validation and debugging
    bool validate_heap() const;
    void dump_free_lists() const;
};

// Global heap instance
extern HeapAllocator* g_heap;

// Heap initialization and kernel allocation functions
void heap_init();
void* kmalloc(size_t size);
void* kmalloc_aligned(size_t size, size_t alignment);
void kfree(void* ptr);
void* krealloc(void* ptr, size_t new_size);

// Heap initialization and kernel allocation functions
void heap_init();
void* kmalloc(size_t size);
void* kmalloc_aligned(size_t size, size_t alignment);
void kfree(void* ptr);
void* krealloc(void* ptr, size_t new_size);

// C-style interface for compatibility
extern "C" {
    void dump_heap_info();
    void* heap_malloc(size_t size);
    void* heap_malloc_aligned(size_t size, size_t alignment);
    void heap_mfree(void* ptr);
    void* heap_realloc(void* ptr, size_t new_size);
    size_t heap_get_size(void* ptr);
    void heap_get_stats(heap_stats* stats);
}

// Inline functions for maximum performance
inline void* operator new(size_t size) {
    return heap_malloc(size);
}

inline void* operator new[](size_t size) {
    return heap_malloc(size);
}

inline void operator delete(void* ptr) noexcept {
    heap_mfree(ptr);
}

inline void operator delete[](void* ptr) noexcept {
    heap_mfree(ptr);
}

inline void operator delete(void* ptr, size_t) noexcept {
    heap_mfree(ptr);
}

inline void operator delete[](void* ptr, size_t) noexcept {
    heap_mfree(ptr);
}

#endif // HEAP_H 