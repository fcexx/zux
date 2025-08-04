#include <heap.h>
#include <debug.h>
#include <paging.h>
#include <string.h>
#include <stdint.h>
#include <vbetty.h>

// Global heap instance
HeapAllocator* g_heap = nullptr;

// Memory pool constructor implementation
memory_pool::memory_pool() : data(nullptr), next(nullptr) {
    // Initialize bitmaps to all free
    for (size_t i = 0; i < NUM_SIZES; i++) {
        for (size_t j = 0; j < POOL_SIZE / 64; j++) {
            bitmap[i][j] = 0xFFFFFFFFFFFFFFFFULL;
        }
    }
}

// Small allocation size classes
static constexpr size_t SMALL_SIZES[] = {16, 32, 64, 128, 256, 512};

// Constructor - initialize heap with given memory region
HeapAllocator::HeapAllocator(void* start_addr, size_t initial_size) 
    : heap_start(nullptr), heap_end(nullptr) {
    
    // Initialize statistics
    memset(&stats, 0, sizeof(stats));
    
    // Initialize free lists
    for (size_t i = 0; i < NUM_BUCKETS; i++) {
        free_lists[i] = nullptr;
    }
    
    // Initialize memory pools
    memory_pools = nullptr;
    
    // Set up initial heap region
    if (start_addr && initial_size > sizeof(heap_block_header)) {
        heap_start = static_cast<heap_block_header*>(start_addr);
        heap_end = heap_start;
        
        // Create initial free block
        heap_start->size = initial_size - sizeof(heap_block_header);
        heap_start->is_free = 1;
        heap_start->magic = MAGIC_NUMBER;
        heap_start->next = nullptr;
        heap_start->prev = nullptr;
        
        // Add to appropriate free list
        add_to_free_list(heap_start);
        
        stats.block_count = 1;
    }
}



// Add block to appropriate free list (LIFO for better cache locality)
void HeapAllocator::add_to_free_list(heap_block_header* block) {
    if (!block || !validate_block(block)) return;
    
    size_t bucket = get_bucket_index(block->size);
    if (bucket >= NUM_BUCKETS) return;
    
    // Insert at head for better cache performance
    block->next = free_lists[bucket];
    block->prev = nullptr;
    
    if (free_lists[bucket]) {
        free_lists[bucket]->prev = block;
    }
    
    free_lists[bucket] = block;
}

// Remove block from free list
void HeapAllocator::remove_from_free_list(heap_block_header* block) {
    if (!block || !validate_block(block)) return;
    
    size_t bucket = get_bucket_index(block->size);
    if (bucket >= NUM_BUCKETS) return;
    
    if (block->prev) {
        block->prev->next = block->next;
    } else {
        free_lists[bucket] = block->next;
    }
    
    if (block->next) {
        block->next->prev = block->prev;
    }
    
    block->next = nullptr;
    block->prev = nullptr;
}

// Find best fit block in free list using binary search optimization
heap_block_header* HeapAllocator::find_best_fit(size_t size) {
    size_t bucket = get_bucket_index(size);
    PrintfQEMU("bucket index=%zu\n", bucket);
    
    // Search in current bucket first
    heap_block_header* best_fit = nullptr;
    size_t best_size = ~0ULL;
    
    for (heap_block_header* current = free_lists[bucket]; current; current = current->next) {
        if (current->size >= size && current->size < best_size) {
            best_fit = current;
            best_size = current->size;
            
            // Perfect fit found
            if (best_size == size) break;
        }
    }
    
    // If not found in current bucket, search in larger buckets
    if (!best_fit) {
        for (size_t i = bucket + 1; i < NUM_BUCKETS; i++) {
            if (free_lists[i]) {
                best_fit = free_lists[i];
                break;
            }
        }
    }
    
    return best_fit;
}

// Split large block if needed (optimized for minimal fragmentation)
heap_block_header* HeapAllocator::split_block(heap_block_header* block, size_t requested_size) {
    if (!block || !validate_block(block)) return nullptr;
    
    // Don't split if remaining size is too small
    size_t remaining_size = block->size - requested_size;
    if (remaining_size < MIN_BLOCK_SIZE + sizeof(heap_block_header)) {
        return block;
    }
    
    // Remove from free list
    remove_from_free_list(block);
    
    // Create new block for remaining space
    heap_block_header* new_block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header) + requested_size
    );
    
    new_block->size = remaining_size - sizeof(heap_block_header);
    new_block->is_free = 1;
    new_block->magic = MAGIC_NUMBER;
    new_block->next = nullptr;
    new_block->prev = nullptr;
    
    // Update original block
    block->size = requested_size;
    block->is_free = 0;
    
    // Add new block to free list
    add_to_free_list(new_block);
    
    stats.block_count++;
    
    return block;
}

// Merge adjacent free blocks (optimized for minimal overhead)
void HeapAllocator::merge_blocks(heap_block_header* block) {
    if (!block || !validate_block(block)) return;
    
    // Try to merge with next block
    heap_block_header* next_block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header) + block->size
    );
    
    if (next_block <= heap_end && validate_block(next_block) && next_block->is_free) {
        // Remove both blocks from free lists
        remove_from_free_list(block);
        remove_from_free_list(next_block);
        
        // Merge blocks
        block->size += sizeof(heap_block_header) + next_block->size;
        
        // Add merged block to free list
        add_to_free_list(block);
        
        stats.block_count--;
    }
    
    // Try to merge with previous block
    if (block > heap_start) {
        // Find previous block by scanning backwards
        heap_block_header* prev_block = heap_start;
        while (prev_block < block) {
            heap_block_header* potential_next = reinterpret_cast<heap_block_header*>(
                reinterpret_cast<uint8_t*>(prev_block) + sizeof(heap_block_header) + prev_block->size
            );
            
            if (potential_next == block) {
                if (validate_block(prev_block) && prev_block->is_free) {
                    // Remove both blocks from free lists
                    remove_from_free_list(prev_block);
                    remove_from_free_list(block);
                    
                    // Merge blocks
                    prev_block->size += sizeof(heap_block_header) + block->size;
                    
                    // Add merged block to free list
                    add_to_free_list(prev_block);
                    
                    stats.block_count--;
                }
                break;
            }
            
            prev_block = potential_next;
        }
    }
}

// Validate block integrity
bool HeapAllocator::validate_block(const heap_block_header* block) const {
    return block && block->magic == MAGIC_NUMBER;
}

// Expand heap by requesting more memory from physical memory manager
bool HeapAllocator::expand_heap(size_t additional_size) {
    // Calculate required pages
    size_t pages_needed = (additional_size + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t bytes_needed = pages_needed * PAGE_SIZE;
    
    // Request memory from physical memory manager
    // This would integrate with your PMM system
    void* new_memory = nullptr; // pmm_alloc_pages(pages_needed);
    
    if (!new_memory) return false;
    
    // Map the new memory
    uint64_t virtual_addr = reinterpret_cast<uint64_t>(heap_end) + sizeof(heap_block_header) + heap_end->size;
    paging_map_range(virtual_addr, reinterpret_cast<uint64_t>(new_memory), bytes_needed, PAGE_PRESENT | PAGE_WRITABLE);
    
    // Create new free block
    heap_block_header* new_block = reinterpret_cast<heap_block_header*>(virtual_addr);
    new_block->size = bytes_needed - sizeof(heap_block_header);
    new_block->is_free = 1;
    new_block->magic = MAGIC_NUMBER;
    new_block->next = nullptr;
    new_block->prev = nullptr;
    
    // Update heap end
    heap_end = new_block;
    
    // Add to free list
    add_to_free_list(new_block);
    
    stats.block_count++;
    
    return true;
}

// Main allocation function with small object optimization
void* HeapAllocator::malloc(size_t size) {
    if (size == 0) return nullptr;
    
    // Use memory pool for small allocations
    if (size <= SMALL_SIZES[sizeof(SMALL_SIZES)/sizeof(SMALL_SIZES[0]) - 1]) {
        return allocate_small(size);
    }
    
    // Find best fit block
    heap_block_header* block = find_best_fit(size);
    
    if (!block) {
        // Try to expand heap
        if (!expand_heap(size + sizeof(heap_block_header))) {
            return nullptr;
        }
        block = find_best_fit(size);
        if (!block) return nullptr;
    }
    
    // Split block if needed
    block = split_block(block, size);
    if (!block) return nullptr;
    
    // Update statistics
    stats.total_allocated += size;
    stats.current_used += size;
    if (stats.current_used > stats.peak_used) {
        stats.peak_used = stats.current_used;
    }
    
    // Return pointer to user data
    return reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header);
}

// Aligned allocation using bit manipulation
void* HeapAllocator::malloc_aligned(size_t size, size_t alignment) {
    if (size == 0 || alignment == 0) return nullptr;
    
    // Ensure alignment is power of 2
    if ((alignment & (alignment - 1)) != 0) return nullptr;
    
    // Calculate required size including alignment overhead
    size_t required_size = size + alignment - 1 + sizeof(heap_block_header);
    
    // Allocate larger block
    heap_block_header* block = find_best_fit(required_size);
    if (!block) {
        if (!expand_heap(required_size)) return nullptr;
        block = find_best_fit(required_size);
        if (!block) return nullptr;
    }
    
    // Remove from free list
    remove_from_free_list(block);
    
    // Calculate aligned address
    uint64_t block_addr = reinterpret_cast<uint64_t>(block) + sizeof(heap_block_header);
    uint64_t aligned_addr = (block_addr + alignment - 1) & ~(alignment - 1);
    
    // Split block if needed
    size_t offset = aligned_addr - block_addr;
    if (offset > 0) {
        // Create header for alignment padding
        heap_block_header* padding_block = block;
        padding_block->size = offset - sizeof(heap_block_header);
        padding_block->is_free = 1;
        padding_block->magic = MAGIC_NUMBER;
        padding_block->next = nullptr;
        padding_block->prev = nullptr;
        
        add_to_free_list(padding_block);
        
        // Update main block
        block = reinterpret_cast<heap_block_header*>(aligned_addr - sizeof(heap_block_header));
        block->size = size;
        block->is_free = 0;
        block->magic = MAGIC_NUMBER;
        block->next = nullptr;
        block->prev = nullptr;
        
        stats.block_count++;
    } else {
        block->size = size;
        block->is_free = 0;
    }
    
    // Update statistics
    stats.total_allocated += size;
    stats.current_used += size;
    if (stats.current_used > stats.peak_used) {
        stats.peak_used = stats.current_used;
    }
    
    return reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header);
}

// Deallocation with automatic merging
void HeapAllocator::mfree(void* ptr) {
    if (!ptr || !is_valid_pointer(ptr)) return;
    
    heap_block_header* block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(ptr) - sizeof(heap_block_header)
    );
    
    if (!validate_block(block)) return;
    
    // Update statistics
    stats.total_freed += block->size;
    stats.current_used -= block->size;
    
    // Mark as free
    block->is_free = 1;
    
    // Merge with adjacent blocks
    merge_blocks(block);
}

// Reallocation with optimization for growing blocks
void* HeapAllocator::realloc(void* ptr, size_t new_size) {
    if (!ptr) return malloc(new_size);
    if (new_size == 0) {
        mfree(ptr);
        return nullptr;
    }
    
    heap_block_header* block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(ptr) - sizeof(heap_block_header)
    );
    
    if (!validate_block(block)) return nullptr;
    
    size_t old_size = block->size;
    
    // If shrinking, just update size
    if (new_size <= old_size) {
        if (new_size + MIN_BLOCK_SIZE + sizeof(heap_block_header) <= old_size) {
            // Split block
            heap_block_header* new_block = reinterpret_cast<heap_block_header*>(
                reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header) + new_size
            );
            
            new_block->size = old_size - new_size - sizeof(heap_block_header);
            new_block->is_free = 1;
            new_block->magic = MAGIC_NUMBER;
            new_block->next = nullptr;
            new_block->prev = nullptr;
            
            block->size = new_size;
            
            add_to_free_list(new_block);
            stats.block_count++;
        }
        
        stats.current_used -= (old_size - new_size);
        return ptr;
    }
    
    // Try to expand in place
    heap_block_header* next_block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header) + old_size
    );
    
    if (next_block <= heap_end && validate_block(next_block) && next_block->is_free) {
        size_t available_size = old_size + sizeof(heap_block_header) + next_block->size;
        if (available_size >= new_size) {
            // Remove next block from free list
            remove_from_free_list(next_block);
            
            // Expand current block
            block->size = new_size;
            
            // Create new free block if there's remaining space
            if (available_size > new_size + MIN_BLOCK_SIZE + sizeof(heap_block_header)) {
                heap_block_header* new_free = reinterpret_cast<heap_block_header*>(
                    reinterpret_cast<uint8_t*>(block) + sizeof(heap_block_header) + new_size
                );
                
                new_free->size = available_size - new_size - sizeof(heap_block_header);
                new_free->is_free = 1;
                new_free->magic = MAGIC_NUMBER;
                new_free->next = nullptr;
                new_free->prev = nullptr;
                
                add_to_free_list(new_free);
            }
            
            stats.current_used += (new_size - old_size);
            return ptr;
        }
    }
    
    // Allocate new block and copy data
    void* new_ptr = malloc(new_size);
    if (!new_ptr) return nullptr;
    
    // Copy data using optimized memory copy
    memcpy(new_ptr, ptr, old_size);
    
    // Free old block
    mfree(ptr);
    
    return new_ptr;
}

// Memory pool allocation for small objects
void* HeapAllocator::allocate_small(size_t size) {
    // Find appropriate size class
    size_t size_class = 0;
    for (size_t i = 0; i < sizeof(SMALL_SIZES)/sizeof(SMALL_SIZES[0]); i++) {
        if (size <= SMALL_SIZES[i]) {
            size_class = i;
            break;
        }
    }
    
    // Find available pool
    memory_pool* pool = memory_pools;
    while (pool) {
        // Check if pool has free slots
        for (size_t i = 0; i < memory_pool::POOL_SIZE / 64; i++) {
            if (pool->bitmap[size_class][i] != 0) {
                // Find first free bit
                uint64_t bitmap = pool->bitmap[size_class][i];
                int bit_pos = __builtin_ctzll(bitmap);
                
                // Mark as allocated
                pool->bitmap[size_class][i] &= ~(1ULL << bit_pos);
                
                // Calculate address
                size_t slot_index = i * 64 + bit_pos;
                size_t offset = slot_index * SMALL_SIZES[size_class];
                
                return pool->data + offset;
            }
        }
        pool = pool->next;
    }
    
    // Create new pool
    pool = static_cast<memory_pool*>(malloc(sizeof(memory_pool)));
    if (!pool) return nullptr;
    
    // Allocate pool data
    pool->data = static_cast<uint8_t*>(malloc(memory_pool::POOL_SIZE));
    if (!pool->data) {
        mfree(pool);
        return nullptr;
    }
    
    // Initialize pool
    *pool = memory_pool();
    pool->data = static_cast<uint8_t*>(malloc(memory_pool::POOL_SIZE));
    
    // Add to pool list
    pool->next = memory_pools;
    memory_pools = pool;
    
    // Allocate from new pool
    pool->bitmap[size_class][0] &= ~1ULL; // Mark first slot as allocated
    return pool->data;
}

// Memory pool deallocation
void HeapAllocator::deallocate_small(void* ptr) {
    // Find pool containing this pointer
    memory_pool* pool = memory_pools;
    while (pool) {
        if (ptr >= pool->data && ptr < pool->data + memory_pool::POOL_SIZE) {
            // Calculate slot index
            size_t offset = static_cast<uint8_t*>(ptr) - pool->data;
            
            // Find size class
            for (size_t size_class = 0; size_class < sizeof(SMALL_SIZES)/sizeof(SMALL_SIZES[0]); size_class++) {
                size_t slot_index = offset / SMALL_SIZES[size_class];
                if (offset % SMALL_SIZES[size_class] == 0 && slot_index < memory_pool::POOL_SIZE / SMALL_SIZES[size_class]) {
                    // Mark as free
                    size_t bitmap_index = slot_index / 64;
                    size_t bit_pos = slot_index % 64;
                    pool->bitmap[size_class][bitmap_index] |= (1ULL << bit_pos);
                    return;
                }
            }
            break;
        }
        pool = pool->next;
    }
}

// Utility functions
size_t HeapAllocator::get_block_size(void* ptr) const {
    if (!is_valid_pointer(ptr)) return 0;
    
    heap_block_header* block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(ptr) - sizeof(heap_block_header)
    );
    
    return validate_block(block) ? block->size : 0;
}

bool HeapAllocator::is_valid_pointer(void* ptr) const {
    if (!ptr) return false;
    
    heap_block_header* block = reinterpret_cast<heap_block_header*>(
        reinterpret_cast<uint8_t*>(ptr) - sizeof(heap_block_header)
    );
    
    return block >= heap_start && block <= heap_end && validate_block(block);
}

void HeapAllocator::get_stats(heap_stats* stats_out) const {
    if (stats_out) {
        *stats_out = stats;
    }
}

// Defragmentation - compact free blocks
void HeapAllocator::defragment() {
    // This is a simplified defragmentation
    // In a real implementation, you would move allocated blocks
    // to compact free space
    
    heap_block_header* current = heap_start;
    while (current <= heap_end) {
        if (validate_block(current) && current->is_free) {
            merge_blocks(current);
        }
        
        current = reinterpret_cast<heap_block_header*>(
            reinterpret_cast<uint8_t*>(current) + sizeof(heap_block_header) + current->size
        );
    }
}

// Validation and debugging
bool HeapAllocator::validate_heap() const {
    heap_block_header* current = heap_start;
    while (current <= heap_end) {
        if (!validate_block(current)) {
            return false;
        }
        current = reinterpret_cast<heap_block_header*>(
            reinterpret_cast<uint8_t*>(current) + sizeof(heap_block_header) + current->size
        );
    }
    return true;
}

extern "C" {
    void dump_heap_info() {
        kprintf("heap started at 0x%p, size %u, end at %p, blocks: %d\n", g_heap->heap_start, g_heap->heap_end - g_heap->heap_start, g_heap->heap_end, g_heap->stats.block_count);
    }
}

void HeapAllocator::dump_free_lists() const {
}

// C-style interface implementation
extern "C" {
    void* heap_malloc(size_t size) {
        return g_heap ? g_heap->malloc(size) : nullptr;
    }
    
    void* heap_malloc_aligned(size_t size, size_t alignment) {
        return g_heap ? g_heap->malloc_aligned(size, alignment) : nullptr;
    }
    
    void heap_mfree(void* ptr) {
        if (g_heap) g_heap->mfree(ptr);
    }
    
    void* heap_realloc(void* ptr, size_t new_size) {
        return g_heap ? g_heap->realloc(ptr, new_size) : nullptr;
    }
    
    size_t heap_get_size(void* ptr) {
        return g_heap ? g_heap->get_block_size(ptr) : 0;
    }
    
    void heap_get_stats(heap_stats* stats) {
        if (g_heap) g_heap->get_stats(stats);
    }
} 