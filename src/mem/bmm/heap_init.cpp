#include <heap.h>
#include <debug.h>
#include <paging.h>
#include <string.h>
// freestanding: avoid <new>

// provide placement-new globally
inline void* operator new(unsigned long, void* p) noexcept { return p; }
inline void  operator delete(void*, void*) noexcept {}

// Heap initialization function
void heap_init() {
    PrintQEMU("heap_init() called\n");
    
    // Allocate initial heap region (8MB)
    static uint8_t heap_region[8 * 1024 * 1024] __attribute__((aligned(4096)));
    
    static bool initialized = false;
    if (!initialized) {
        PrintQEMU("Initializing heap for the first time\n");

        // Compute allocator object placement and data span
        uint8_t* region_start = heap_region;
        size_t region_size = sizeof(heap_region);
        // Place allocator at start
        g_heap = reinterpret_cast<HeapAllocator*>(region_start);
        uint8_t* heap_data = region_start + sizeof(HeapAllocator);
        size_t heap_size = region_size - sizeof(HeapAllocator);

        // Construct allocator with placement-new
        new (g_heap) HeapAllocator(heap_data, heap_size);
            
            PrintfQEMU("Heap initialized with %llu bytes available\n", (unsigned long long)heap_size);
        initialized = true;
    }
}

// Heap allocation wrapper for kernel use
void* kmalloc(size_t size) {
    void* p = g_heap ? g_heap->malloc(size) : nullptr;
    // PrintfQEMU("[heap.api] kmalloc(%zu) -> %p\n", size, p);
    return p;
}

void* kmalloc_aligned(size_t size, size_t alignment) {
    void* p = g_heap ? g_heap->malloc_aligned(size, alignment) : nullptr;
    // PrintfQEMU("[heap.api] kmalloc_aligned(%zu,%zu) -> %p\n", size, alignment, p);
    return p;
}

void kfree(void* ptr) {
    // PrintfQEMU("[heap.api] kfree(%p)\n", ptr);
    if (g_heap) g_heap->mfree(ptr);
}

void* krealloc(void* ptr, size_t new_size) {
    void* p = g_heap ? g_heap->realloc(ptr, new_size) : nullptr;
    // PrintfQEMU("[heap.api] krealloc(%p,%zu) -> %p\n", ptr, new_size, p);
    return p;
}