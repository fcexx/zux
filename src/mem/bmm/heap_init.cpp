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
                qemu_log_printf("Heap initialized with %llu bytes available\n", (unsigned long long)heap_size);
                qemu_log_printf("[heap init] g_heap=%p heap_data=%p heap_size=0x%llx sizeof(HeapAllocator)=%zu\n",
                                   (void*)g_heap, (void*)heap_data, (unsigned long long)heap_size, (size_t)sizeof(HeapAllocator));
                if (g_heap) {
                        qemu_log_printf("[heap init] heap_mem_start=%p heap_mem_end=%p heap_start=%p heap_start->size=%zu\n",
                                           (void*)g_heap->heap_mem_start, (void*)g_heap->heap_mem_end,
                                           (void*)g_heap->heap_start, (size_t)(g_heap->heap_start?g_heap->heap_start->size:0));
                }
                initialized = true;
        }
}

// Allocation history for debugging (circular buffer)
static struct {
        size_t size;
        void* ptr;
        void* caller;
} alloc_history[64];
static int alloc_hist_idx = 0;

extern "C" void dump_heap_info();

static void record_alloc(size_t size, void* ptr, void* caller) {
        alloc_history[alloc_hist_idx].size = size;
        alloc_history[alloc_hist_idx].ptr = ptr;
        alloc_history[alloc_hist_idx].caller = caller;
        alloc_hist_idx = (alloc_hist_idx + 1) % (int)(sizeof(alloc_history)/sizeof(alloc_history[0]));
}

extern "C" void dump_alloc_history(void) {
        qemu_log_printf("[alloc_hist] last allocations:\n");
        int n = (int)(sizeof(alloc_history)/sizeof(alloc_history[0]));
        int i = alloc_hist_idx;
        for (int k = 0; k < n; ++k) {
                i = (i - 1 + n) % n;
                if (alloc_history[i].ptr == nullptr && alloc_history[i].size == 0) continue;
                qemu_log_printf("[alloc_hist] #%d size=%zu ptr=%p caller=%p\n", k, alloc_history[i].size, alloc_history[i].ptr, alloc_history[i].caller);
        }
}

// Heap allocation wrapper for kernel use
void* kmalloc(size_t size) {
        void* p = g_heap ? g_heap->malloc(size) : nullptr;
        // Log allocation with return address (caller) for debugging
        void* ra = __builtin_return_address(0);
        // Уменьшаем шум логов и избегаем огромных дампов, которые могут «вешать» консоль
        // logging disabled to avoid boot-time stalls on slow consoles
        record_alloc(size, p, ra);
        return p;
}

void* kmalloc_aligned(size_t size, size_t alignment) {
        void* p = g_heap ? g_heap->malloc_aligned(size, alignment) : nullptr;
        void* ra = __builtin_return_address(0);
        // logging disabled to avoid boot-time stalls on slow consoles
        record_alloc(size, p, ra);
        return p;
}

void kfree(void* ptr) {
        void* ra = __builtin_return_address(0);
        if (g_heap) g_heap->mfree(ptr);
}

void* krealloc(void* ptr, size_t new_size) {
        void* p = g_heap ? g_heap->realloc(ptr, new_size) : nullptr;
        // qemu_log_printf("[heap.api] krealloc(%p,%zu) -> %p\n", ptr, new_size, p);
        return p;
}