#include <heap.h>
#include <debug.h>
#include <paging.h>
#include <string.h>

// Heap initialization function
void heap_init() {
    PrintQEMU("heap_init() called\n");
    
    // Allocate initial heap region (2MB for double buffering)
    // In a real system, this would be allocated from the physical memory manager
    static uint8_t heap_region[2 * 1024 * 1024] __attribute__((aligned(4096)));
    
    // Initialize global heap instance
    static bool initialized = false;
    if (!initialized) {
        PrintQEMU("Initializing heap for the first time\n");
        // Create heap allocator in the heap region
        g_heap = reinterpret_cast<HeapAllocator*>(heap_region);
        // Manually initialize the heap allocator
        g_heap->heap_start = nullptr;
        g_heap->heap_end = nullptr;
        g_heap->memory_pools = nullptr;
        memset(&g_heap->stats, 0, sizeof(g_heap->stats));
        
        // Initialize free lists
        for (size_t i = 0; i < 32; i++) {
            g_heap->free_lists[i] = nullptr;
        }
        
        // Set up initial heap region
        uint8_t* heap_data = heap_region + sizeof(HeapAllocator);
        size_t heap_size = sizeof(heap_region) - sizeof(HeapAllocator);
        
        if (heap_size > sizeof(heap_block_header)) {
            g_heap->heap_start = reinterpret_cast<heap_block_header*>(heap_data);
            g_heap->heap_end = g_heap->heap_start;
            
            // Create initial free block
            g_heap->heap_start->size = heap_size - sizeof(heap_block_header);
            g_heap->heap_start->is_free = 1;
            g_heap->heap_start->magic = 0xDEADBEEFCAFEBABE;
            g_heap->heap_start->next = nullptr;
            g_heap->heap_start->prev = nullptr;
            
            // Add to free list
            g_heap->add_to_free_list(g_heap->heap_start);
            
            g_heap->stats.block_count = 1;
            
            PrintfQEMU("Heap initialized with %llu bytes available\n", (unsigned long long)heap_size);
        } else {
            PrintQEMU("[heap_init] Not enough space for heap block header!\n");
        }
        
        initialized = true;
    }
}

// Heap allocation wrapper for kernel use
void* kmalloc(size_t size) {
    return g_heap ? g_heap->malloc(size) : nullptr;
}

void* kmalloc_aligned(size_t size, size_t alignment) {
    return g_heap ? g_heap->malloc_aligned(size, alignment) : nullptr;
}

void kfree(void* ptr) {
    if (g_heap) g_heap->mfree(ptr);
}

void* krealloc(void* ptr, size_t new_size) {
    return g_heap ? g_heap->realloc(ptr, new_size) : nullptr;
}