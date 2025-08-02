ENTRY(_start)

SECTIONS
{
    . = 0x100000;
    
                    .multiboot2 : {
                    *(.multiboot2)
                }
    
    .text : {
        *(.text)
    }
    
    .rodata : {
        *(.rodata)
    }
    
    .data : {
        *(.data)
    }
    
    .bss : {
        *(.bss)
    }
} 