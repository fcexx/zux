#include "mbparcer.h"
#include "debug.h"

Multiboot2Parser::Multiboot2Parser(void* info, uint32_t magic) 
    : multiboot2_info(info), multiboot2_magic(magic) {
}

bool Multiboot2Parser::isValid() const {
    return multiboot2_magic == 0x36D76289 && multiboot2_info != nullptr;
}

template<typename T>
T* Multiboot2Parser::findTag(uint32_t type) const {
    if (!isValid()) {
        return nullptr;
    }
    
    // Multiboot2 info starts with total size
    uint32_t* info_ptr = static_cast<uint32_t*>(multiboot2_info);
    uint32_t total_size = *info_ptr;
    
    // First tag starts after the size field
    multiboot2_tag* tag = reinterpret_cast<multiboot2_tag*>(info_ptr + 1);
    
    while (tag->type != MULTIBOOT2_TAG_TYPE_END) {
        if (tag->type == type) {
            return reinterpret_cast<T*>(tag);
        }
        
        // Move to next tag (size includes the tag header)
        uint32_t next_offset = (tag->size + 7) & ~7;
        if (next_offset == 0) {
            return nullptr;
        }
        
        tag = reinterpret_cast<multiboot2_tag*>(
            reinterpret_cast<uint8_t*>(tag) + next_offset
        );
    }
    
    return nullptr;
}

const char* Multiboot2Parser::getCommandLine() const {
    multiboot2_tag_string* tag = findTag<multiboot2_tag_string>(MULTIBOOT2_TAG_TYPE_CMDLINE);
    return tag ? tag->string : nullptr;
}

const char* Multiboot2Parser::getBootLoaderName() const {
    multiboot2_tag_string* tag = findTag<multiboot2_tag_string>(MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME);
    return tag ? tag->string : nullptr;
}

multiboot2_tag_framebuffer* Multiboot2Parser::getFramebufferInfo() const {
    return findTag<multiboot2_tag_framebuffer>(MULTIBOOT2_TAG_TYPE_FRAMEBUFFER);
}

multiboot2_tag_mmap* Multiboot2Parser::getMemoryMap() const {
    return findTag<multiboot2_tag_mmap>(MULTIBOOT2_TAG_TYPE_MMAP);
}

multiboot2_tag_basic_meminfo* Multiboot2Parser::getBasicMemInfo() const {
    return findTag<multiboot2_tag_basic_meminfo>(MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO);
}
