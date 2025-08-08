#include <elf.h>
#include <fs_interface.h>
#include <heap.h>
#include <paging.h>
#include <string.h>
#include <debug.h>

// minimal uintptr_t for freestanding
typedef unsigned long long uintptr_t;

// ELF64 structures (minimal)
struct __attribute__((packed)) Elf64_Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct __attribute__((packed)) Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

static const uint32_t PT_LOAD = 1;
static const unsigned EI_MAG0=0, EI_MAG1=1, EI_MAG2=2, EI_MAG3=3, EI_CLASS=4, EI_DATA=5;
static const unsigned char ELFMAG0=0x7f, ELFMAG1='E', ELFMAG2='L', ELFMAG3='F';
static const unsigned char ELFCLASS64=2; // 64-bit
static const unsigned char ELFDATA2LSB=1; // little-endian

int elf64_load_process(const char* path, uint64_t user_stack_size,
                       uint64_t* out_entry, uint64_t* out_user_stack_top) {
    // критическая секция на время загрузки (heap/fs/paging не реентерабельны)
    uint64_t saved_rflags; asm volatile("pushfq; pop %0" : "=r"(saved_rflags));
    asm volatile("cli" ::: "memory");

    if (!fs_is_initialized()) { PrintQEMU("[elf] fs not initialized\n"); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    fs_file_t* f = fs_open(path, FS_OPEN_READ);
    if (!f) { PrintfQEMU("[elf] open failed: %s\n", path); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    PrintfQEMU("[elf] open ok: file=%p\n", f);

    // Read ELF header
    Elf64_Ehdr eh{};
    if (fs_read(f, &eh, sizeof(eh)) != (int)sizeof(eh)) { fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    if (!(eh.e_ident[EI_MAG0]==ELFMAG0 && eh.e_ident[EI_MAG1]==ELFMAG1 && eh.e_ident[EI_MAG2]==ELFMAG2 && eh.e_ident[EI_MAG3]==ELFMAG3)) { fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB) { fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }

    PrintfQEMU("[elf] hdr: e_entry=0x%llx e_phoff=%llu e_phentsize=%u e_phnum=%u\n",
               (unsigned long long)eh.e_entry,
               (unsigned long long)eh.e_phoff,
               (unsigned)eh.e_phentsize,
               (unsigned)eh.e_phnum);
    if (eh.e_phentsize != sizeof(Elf64_Phdr)) {
        PrintfQEMU("[elf] WARN: e_phentsize=%u != sizeof(Phdr)=%u\n", (unsigned)eh.e_phentsize, (unsigned)sizeof(Elf64_Phdr));
    }

    // Read program headers
    if (fs_seek(f, (int)eh.e_phoff, FS_SEEK_SET) < 0) { PrintQEMU("[elf] seek phoff failed\n"); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    int phdr_table_size = (int)eh.e_phnum * (int)eh.e_phentsize;
    void* ph_buf = kmalloc(phdr_table_size);
    if (!ph_buf) { PrintQEMU("[elf] kmalloc phdr table failed\n"); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    int rr_tab = fs_read(f, ph_buf, phdr_table_size);
    if (rr_tab != phdr_table_size) { PrintfQEMU("[elf] read phdr table failed: got %d\n", rr_tab); kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }

    // Map PT_LOAD segments
    for (int i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_memsz == 0) continue;

        PrintfQEMU("[elf] PH[%d]: off=%llu vaddr=0x%llx filesz=%llu memsz=%llu flags=0x%x\n",
                   i, (unsigned long long)ph->p_offset, (unsigned long long)ph->p_vaddr,
                   (unsigned long long)ph->p_filesz, (unsigned long long)ph->p_memsz, (unsigned)ph->p_flags);

        uint64_t seg_size = (ph->p_filesz > ph->p_memsz) ? ph->p_filesz : ph->p_memsz;
        uint64_t va_start = ph->p_vaddr & ~0xFFFULL;
        uint64_t va_end   = (ph->p_vaddr + seg_size + 0xFFFULL) & ~0xFFFULL;
        uint64_t map_size = va_end - va_start;

        uint64_t backing_size = map_size + 0x1000;
        void* backing_raw = kmalloc((size_t)backing_size);
        if (!backing_raw) { kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
        uint64_t backing = ((uint64_t)backing_raw + 0xFFFULL) & ~0xFFFULL; // aligned

        uint64_t flags = PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
        for (uint64_t off = 0; off < map_size; off += 0x1000ULL) {
            paging_map_page(va_start + off, backing + off, flags);
        }

        if (fs_seek(f, (int)ph->p_offset, FS_SEEK_SET) < 0) { PrintfQEMU("[elf] seek to seg %d offset %llu failed\n", i, (unsigned long long)ph->p_offset); kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
        if (ph->p_filesz) {
            int to_read = (int)ph->p_filesz;
            void* seg = (void*)(uintptr_t)ph->p_vaddr;
            int rr = fs_read(f, seg, to_read);
            PrintfQEMU("[elf] read seg %d: requested=%d got=%d\n", i, to_read, rr);
            if (rr != to_read) { kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
        }
        if (ph->p_memsz > ph->p_filesz) {
            uint64_t bss_start = ph->p_vaddr + ph->p_filesz;
            uint64_t bss_len   = ph->p_memsz - ph->p_filesz;
            memset((void*)(uintptr_t)bss_start, 0, bss_len);
        }
    }

    // Дополнительная проверка: e_entry должен попадать в любой PT_LOAD
    bool entry_ok = false; uint64_t first_load_vaddr = 0; bool have_first=false;
    for (int i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if(!have_first){ first_load_vaddr = ph->p_vaddr; have_first=true; }
        uint64_t seg_size = (ph->p_filesz > ph->p_memsz) ? ph->p_filesz : ph->p_memsz;
        uint64_t start = ph->p_vaddr;
        uint64_t end   = ph->p_vaddr + seg_size;
        if (eh.e_entry >= start && eh.e_entry < end) { entry_ok = true; break; }
    }
    if (!entry_ok) { PrintfQEMU("[elf] entry 0x%llx not in PT_LOAD, forcing to 0x%llx\n", (unsigned long long)eh.e_entry, (unsigned long long)first_load_vaddr); eh.e_entry = first_load_vaddr; }

    kfree(ph_buf);
    fs_close(f);

    // Выделение и маппинг пользовательского стека: фиксированный VA топ и постраничная физическая память
    if (user_stack_size < 16384) user_stack_size = 16384;
    const uint64_t USER_STACK_TOP_VA = 0x800000ULL; // 8 MiB, внутри identity-map 64 MiB
    uint64_t u_top = USER_STACK_TOP_VA;
    uint64_t s_start = (u_top - user_stack_size) & ~0xFFFULL;
    uint64_t s_end   = (u_top + 0xFFFULL) & ~0xFFFULL;

    for (uint64_t va = s_start; va < s_end; va += 0x1000ULL) {
        void* page_raw = kmalloc(0x2000); // запас под выравнивание
        if (!page_raw) { asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
        uint64_t page_phys = ((uint64_t)page_raw + 0xFFFULL) & ~0xFFFULL;
        paging_map_page(va, page_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
        memset((void*)(uintptr_t)va, 0, 0x1000);
    }

    if (out_entry) *out_entry = eh.e_entry;
    if (out_user_stack_top) *out_user_stack_top = u_top - 8; // обеспечить RSP%16==8 на входе в _start

    // восстановить флаги прерываний
    asm volatile("push %0; popfq"::"r"(saved_rflags):"memory");
    return 0;
} 