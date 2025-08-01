#ifndef MULTIBOOT2_HEADER_H
#define MULTIBOOT2_HEADER_H

#define MULTIBOOT2_MAGIC          0x36D76289
#define MULTIBOOT2_ARCHITECTURE_I386      0
#define MULTIBOOT2_HEADER_TAG_END 0

#define MULTIBOOT2_HEADER_TAG_INFORMATION_FRAMEBUFFER 5

#define MULTIBOOT2_FRAMEBUFFER_TYPE_RGB 1

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