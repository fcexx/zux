section .multiboot2
    BITS 32
    align 8
    multiboot2_header:
        ; magic
        dd 0xe85250d6
        ; architecture i386
        dd 0
        ; header length
        dd multiboot2_header_end - multiboot2_header
        ; checksum
        dd -(0xe85250d6 + 0 + (multiboot2_header_end - multiboot2_header))

    ; framebuffer tag
    align 8
    dd 5 ; type: MULTIBOOT2_HEADER_TAG_INFORMATION_FRAMEBUFFER
    dd 20 ; size
    dd 640 ; width
    dd 480 ; height
    dd 32 ; depth

    ; end tag
    align 8
    dd 0 ; type: MULTIBOOT2_HEADER_TAG_END
    dd 8 ; size

    multiboot2_header_end:

section .text
    BITS 32
    global _start
    extern kernel_main

_start:
    ; Save multiboot2 info
    mov [multiboot2_info], ebx
    mov [multiboot2_magic], eax

    ; Disable interrupts
    cli

    ; Set up page tables
    ; Clear all page tables
    mov edi, page_table_l4
    xor eax, eax
    mov ecx, 4096
    rep stosd

    ; Set up L4 page table
    mov eax, page_table_l3
    or eax, 0b11 ; present + writable
    mov [page_table_l4], eax

    ; Set up L3 page table
    mov eax, page_table_l2
    or eax, 0b11 ; present + writable
    mov [page_table_l3], eax

    ; Set up L2 page table
    mov eax, page_table_l1
    or eax, 0b11 ; present + writable
    mov [page_table_l2], eax

    ; Set up L1 page table (identity map first 2MB)
    mov edi, page_table_l1
    mov eax, 0x00000000
    mov ecx, 512
.l1_loop:
    mov edx, eax
    or edx, 0b11 ; present + writable
    mov [edi], edx
    add eax, 0x1000 ; 4KB
    add edi, 8
    loop .l1_loop

    ; Load page table
    mov eax, page_table_l4
    mov cr3, eax

    ; Enable PAE
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    ; Enable long mode
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    ; Load GDT for long mode
    lgdt [gdt64_ptr]

    ; Far jump to long mode
    jmp 0x08:.long_mode

    BITS 64
.long_mode:
    ; Set up segment registers
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Set up stack
    mov rsp, stack_top

    ; Call kernel_main with multiboot2 info
    mov rdi, [multiboot2_info] ; first argument
    mov rsi, [multiboot2_magic] ; second argument
    call kernel_main

    ; Loop indefinitely
    cli
.loop:
    hlt
    jmp .loop

section .data
    BITS 64
    align 4096
    page_table_l4:
        times 512 dq 0

    page_table_l3:
        times 512 dq 0

    page_table_l2:
        times 512 dq 0

    page_table_l1:
        times 512 dq 0

    align 8
    gdt64:
        ; null descriptor
        dq 0
        ; code descriptor (selector 0x08)
        dw 0x0000 ; limit
        dw 0x0000 ; base
        db 0x00 ; base
        db 0x9A ; access (present, ring 0, code, executable, non-conforming, readable)
        db 0x20 ; flags (granularity 4KB, 64-bit default operand size, long mode) + limit
        db 0x00 ; base
        ; data descriptor (selector 0x10)
        dw 0x0000 ; limit
        dw 0x0000 ; base
        db 0x00 ; base
        db 0x92 ; access (present, ring 0, data, writable)
        db 0x20 ; flags (granularity 4KB, 64-bit default operand size, long mode) + limit
        db 0x00 ; base

    gdt64_ptr:
        dw gdt64_ptr - gdt64 - 1
        dq gdt64

    multiboot2_info:
        dq 0

    multiboot2_magic:
        dd 0

section .bss
    BITS 64
    align 4096
    stack_bottom:
        resb 4096 * 4 ; 16KB stack
    stack_top: 