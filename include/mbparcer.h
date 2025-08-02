#ifndef MBPARCER_H
#define MBPARCER_H

#include "multiboot2.h"

// Multiboot2 tag types
#define MULTIBOOT2_TAG_TYPE_END                   0
#define MULTIBOOT2_TAG_TYPE_CMDLINE               1
#define MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME      2
#define MULTIBOOT2_TAG_TYPE_MODULE                3
#define MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO         4
#define MULTIBOOT2_TAG_TYPE_BOOTDEV               5
#define MULTIBOOT2_TAG_TYPE_MMAP                  6
#define MULTIBOOT2_TAG_TYPE_VBE                   7
#define MULTIBOOT2_TAG_TYPE_FRAMEBUFFER           8
#define MULTIBOOT2_TAG_TYPE_ELF_SECTIONS          9
#define MULTIBOOT2_TAG_TYPE_APM                   10
#define MULTIBOOT2_TAG_TYPE_EFI_32                11
#define MULTIBOOT2_TAG_TYPE_EFI_64                12
#define MULTIBOOT2_TAG_TYPE_SMBIOS                13
#define MULTIBOOT2_TAG_TYPE_ACPI_OLD              14
#define MULTIBOOT2_TAG_TYPE_ACPI_NEW              15
#define MULTIBOOT2_TAG_TYPE_NETWORK               16
#define MULTIBOOT2_TAG_TYPE_EFI_MMAP              17
#define MULTIBOOT2_TAG_TYPE_EFI_BS                18
#define MULTIBOOT2_TAG_TYPE_EFI_32_HANDLE         19
#define MULTIBOOT2_TAG_TYPE_EFI_64_HANDLE         20
#define MULTIBOOT2_TAG_TYPE_LOAD_BASE_ADDR        21

class Multiboot2Parser {
private:
    void* multiboot2_info;
    uint32_t multiboot2_magic;

    template<typename T>
    T* findTag(uint32_t type) const;

public:
    Multiboot2Parser(void* info, uint32_t magic);
    
    bool isValid() const;
    
    const char* getCommandLine() const;
    const char* getBootLoaderName() const;
    multiboot2_tag_framebuffer* getFramebufferInfo() const;
    multiboot2_tag_mmap* getMemoryMap() const;
    multiboot2_tag_basic_meminfo* getBasicMemInfo() const;
};

#endif // MBPARCER_H
