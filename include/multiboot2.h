#ifndef MULTIBOOT2_HEADER_H
#define MULTIBOOT2_HEADER_H

#include <stdint.h>

#define MULTIBOOT2_MAGIC                  0x36D76289
#define MULTIBOOT2_ARCHITECTURE_I386          0
#define MULTIBOOT2_HEADER_TAG_END 0

#define MULTIBOOT2_HEADER_TAG_INFORMATION_FRAMEBUFFER 5

#define MULTIBOOT2_FRAMEBUFFER_TYPE_RGB 1

struct multiboot2_tag {
        uint32_t type;
        uint32_t size;
};

struct multiboot2_tag_string {
        uint32_t type;
        uint32_t size;
        char string[0];
};

struct multiboot2_tag_module {
        uint32_t type;
        uint32_t size;
        uint32_t mod_start;
        uint32_t mod_end;
        char cmdline[0];
};

struct multiboot2_tag_basic_meminfo {
        uint32_t type;
        uint32_t size;
        uint32_t mem_lower;
        uint32_t mem_upper;
};

struct multiboot2_tag_bootdev {
        uint32_t type;
        uint32_t size;
        uint32_t biosdev;
        uint32_t partition;
        uint32_t subpartition;
};

struct multiboot2_tag_mmap_entry {
        uint64_t addr;
        uint64_t len;
        uint32_t type;
        uint32_t zero;
};

struct multiboot2_tag_mmap {
        uint32_t type;
        uint32_t size;
        uint32_t entry_size;
        uint32_t entry_version;
        multiboot2_tag_mmap_entry entries[0];
};

struct multiboot2_tag_framebuffer {
        uint32_t type;
        uint32_t size;
        uint64_t framebuffer_addr;
        uint32_t framebuffer_pitch;
        uint32_t framebuffer_width;
        uint32_t framebuffer_height;
        uint8_t framebuffer_bpp;
        uint8_t framebuffer_type;
        uint8_t reserved;
        union {
                struct {
                        uint32_t framebuffer_palette_num_colors;
                        struct {
                                uint8_t red;
                                uint8_t green;
                                uint8_t blue;
                        } framebuffer_palette[0];
                };
                struct {
                        uint8_t framebuffer_red_field_position;
                        uint8_t framebuffer_red_mask_size;
                        uint8_t framebuffer_green_field_position;
                        uint8_t framebuffer_green_mask_size;
                        uint8_t framebuffer_blue_field_position;
                        uint8_t framebuffer_blue_mask_size;
                };
        };
};

struct multiboot_header {
        unsigned int magic;
        unsigned int architecture;
        unsigned int header_length;
        unsigned int checksum;
};

struct multiboot_header_tag {
        unsigned int type;
        unsigned int size;
};

struct multiboot_header_tag_framebuffer {
        unsigned int type;
        unsigned int size;
        unsigned int width;
        unsigned int height;
        unsigned int depth;
};

#endif // MULTIBOOT2_HEADER_H