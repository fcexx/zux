#include <elf.h>
#include <fs_interface.h>
#include <heap.h>
#include <paging.h>
#include <string.h>
#include <debug.h>

// minimal uintptr_t for freestanding
typedef unsigned long long uintptr_t;

// --- Local ELF constants (freestanding, no libc elf.h) ---
#ifndef EI_MAG0
#define EI_MAG0   0
#endif
#ifndef EI_MAG1
#define EI_MAG1   1
#endif
#ifndef EI_MAG2
#define EI_MAG2   2
#endif
#ifndef EI_MAG3
#define EI_MAG3   3
#endif
#ifndef ELFMAG0
#define ELFMAG0   0x7f
#endif
#ifndef ELFMAG1
#define ELFMAG1   'E'
#endif
#ifndef ELFMAG2
#define ELFMAG2   'L'
#endif
#ifndef ELFMAG3
#define ELFMAG3   'F'
#endif
#ifndef EI_CLASS
#define EI_CLASS  4
#endif
#ifndef EI_DATA
#define EI_DATA   5
#endif
#ifndef ELFCLASS64
#define ELFCLASS64 2
#endif
#ifndef ELFDATA2LSB
#define ELFDATA2LSB 1
#endif
#ifndef PT_LOAD
#define PT_LOAD   1
#endif
#ifndef PT_DYNAMIC
#define PT_DYNAMIC 2
#endif
#ifndef DT_NULL
#define DT_NULL   0
#endif
#ifndef DT_RELA
#define DT_RELA   7
#endif
#ifndef DT_RELASZ
#define DT_RELASZ 8
#endif
#ifndef DT_RELAENT
#define DT_RELAENT 9
#endif
#ifndef DT_REL
#define DT_REL    17
#endif
#ifndef DT_RELSZ
#define DT_RELSZ  18
#endif
#ifndef DT_RELENT
#define DT_RELENT 19
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELR
#define DT_RELR   36
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif

// Экспорт auxv параметров последней загруженной программы
extern "C" uint64_t elf_last_at_phdr  = 0;
extern "C" uint64_t elf_last_at_phent = 0;
extern "C" uint64_t elf_last_at_phnum = 0;
extern "C" uint64_t elf_last_at_entry = 0;
// База для brk: конец PT_LOAD (выровненный вверх)
extern "C" uint64_t elf_last_brk_base = 0;
// База загрузки последней программы (для эвристик ребейза адресов в #GP)
extern "C" uint64_t elf_last_load_base = 0;

// Простой статический пул страниц (16 МБ) для маппинга ELF и пользовательского стека
static uint8_t elf_page_pool[16 * 1024 * 1024] __attribute__((aligned(4096)));
static uint32_t elf_page_pool_used_pages = 0; // по 4К
static inline void* elf_alloc_page4k() {
    const uint32_t max_pages = (uint32_t)(sizeof(elf_page_pool) / 4096);
    if (elf_page_pool_used_pages >= max_pages) return nullptr;
    void* p = (void*)(elf_page_pool + (size_t)elf_page_pool_used_pages * 4096);
    elf_page_pool_used_pages++;
    return p;
}

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

struct __attribute__((packed)) Elf64_Dyn {
    int64_t  d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
};

typedef uint64_t Elf64_Addr;
struct __attribute__((packed)) Elf64_Rela {
    Elf64_Addr r_offset;
    uint64_t   r_info;
    int64_t    r_addend;
};

#define ELF64_R_SYM(i)   ((i) >> 32)
#define ELF64_R_TYPE(i)  ((i) & 0xffffffff)
#define R_X86_64_RELATIVE 8
#define R_X86_64_64       1
#define R_X86_64_GLOB_DAT 6

struct __attribute__((packed)) Elf64_Rel
{
    uint64_t r_offset;
    uint64_t r_info;
};

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

    // Determine load base for ET_DYN (PIE)
    uint64_t load_base = 0;
    const uint16_t ET_DYN = 3;
    if (eh.e_type == ET_DYN) {
        load_base = 0x20000000ULL; // 512 MiB — вне области кучи ядра и identity 64 MiB
    }

    // Read program headers
    if (fs_seek(f, (int)eh.e_phoff, FS_SEEK_SET) < 0) { PrintQEMU("[elf] seek phoff failed\n"); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    int phdr_table_size = (int)eh.e_phnum * (int)eh.e_phentsize;
    void* ph_buf = kmalloc(phdr_table_size);
    if (!ph_buf) { PrintQEMU("[elf] kmalloc phdr table failed\n"); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
    int rr_tab = fs_read(f, ph_buf, phdr_table_size);
    if (rr_tab != phdr_table_size) { PrintfQEMU("[elf] read phdr table failed: got %d\n", rr_tab); kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }

    // Map PT_LOAD segments
    uint64_t max_load_end = 0;
    uint64_t min_ptload_vaddr = ~0ULL;
    for (int i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_memsz == 0) continue;

        if (ph->p_vaddr < min_ptload_vaddr) min_ptload_vaddr = ph->p_vaddr;

        PrintfQEMU("[elf] PH[%d]: off=%llu vaddr=0x%llx filesz=%llu memsz=%llu flags=0x%x\n",
                   i, (unsigned long long)ph->p_offset, (unsigned long long)ph->p_vaddr,
                   (unsigned long long)ph->p_filesz, (unsigned long long)ph->p_memsz, (unsigned)ph->p_flags);

        uint64_t seg_size = (ph->p_filesz > ph->p_memsz) ? ph->p_filesz : ph->p_memsz;
        uint64_t seg_va   = load_base + ph->p_vaddr;
        uint64_t va_start = seg_va & ~0xFFFULL;
        uint64_t va_end   = (seg_va + seg_size + 0xFFFULL) & ~0xFFFULL;
        uint64_t map_size = va_end - va_start;

        uint64_t flags = PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
        for (uint64_t off = 0; off < map_size; off += 0x1000ULL) {
            void* page = elf_alloc_page4k();
            if (!page) page = kmalloc_aligned(0x1000, 0x1000);
            if (!page) { kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
            paging_map_page(va_start + off, (uint64_t)page, flags);
        }

        if (ph->p_filesz) {
            // Чтение сегмента из нового дескриптора (чтобы избежать багов seek у VFS на исходном f)
            fs_file_t* fseg = fs_open(path, FS_OPEN_READ);
            if (!fseg) { PrintfQEMU("[elf] open for seg %d failed\n", i); kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
            if (fs_seek(fseg, (int)ph->p_offset, FS_SEEK_SET) < 0) {
                PrintfQEMU("[elf] seek to seg %d offset %llu failed\n", i, (unsigned long long)ph->p_offset);
                fs_close(fseg);
                kfree(ph_buf); fs_close(f);
                asm volatile("push %0; popfq"::"r"(saved_rflags):"memory");
                return -1;
            }
            uint64_t remaining = ph->p_filesz;
            uint8_t* dst = (uint8_t*)(uintptr_t)(load_base + ph->p_vaddr);
            static uint8_t kbuf_static[4096] __attribute__((aligned(16)));
            const size_t CHUNK = sizeof(kbuf_static);
            while (remaining) {
                size_t want = (remaining > CHUNK) ? CHUNK : (size_t)remaining;
                int rr = fs_read(fseg, kbuf_static, want);
                if (rr <= 0) { fs_close(fseg); kfree(ph_buf); fs_close(f); asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
                memcpy(dst, kbuf_static, (size_t)rr);
                dst += (size_t)rr;
                remaining -= (uint64_t)rr;
            }
            fs_close(fseg);
        }
        if (ph->p_memsz > ph->p_filesz) {
            uint64_t bss_start = load_base + ph->p_vaddr + ph->p_filesz;
            uint64_t bss_len   = ph->p_memsz - ph->p_filesz;
            memset((void*)(uintptr_t)bss_start, 0, bss_len);
        }
        uint64_t seg_end = load_base + ph->p_vaddr + ph->p_memsz;
        if (seg_end > max_load_end) max_load_end = seg_end;
    }

    // Если это PIE (ET_DYN), применим базовые релокации R_X86_64_RELATIVE из PT_DYNAMIC
    if (eh.e_type == 3 /*ET_DYN*/){
        uint64_t dyn_vaddr = 0, dyn_memsz = 0;
        for (int i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
            if (ph->p_type == PT_DYNAMIC) { dyn_vaddr = ph->p_vaddr; dyn_memsz = ph->p_memsz; break; }
        }
        if (dyn_vaddr && dyn_memsz){
            Elf64_Dyn* dyn = (Elf64_Dyn*)(uintptr_t)(load_base + dyn_vaddr);
            uint64_t rela = 0, relasz = 0, relaent = sizeof(Elf64_Rela);
            uint64_t rel  = 0, relsz  = 0, relent  = sizeof(Elf64_Rel);
            uint64_t relr = 0, relrsz = 0, relrent = sizeof(uint64_t);
            for (Elf64_Dyn* d = dyn; d && d->d_tag != DT_NULL; ++d){
                if (d->d_tag == DT_RELA)    rela    = d->d_un.d_ptr;
                else if (d->d_tag == DT_RELASZ)  relasz  = d->d_un.d_val;
                else if (d->d_tag == DT_RELAENT) relaent = d->d_un.d_val;
                else if (d->d_tag == DT_REL)     rel     = d->d_un.d_ptr;
                else if (d->d_tag == DT_RELSZ)   relsz   = d->d_un.d_val;
                else if (d->d_tag == DT_RELENT)  relent  = d->d_un.d_val;
                else if (d->d_tag == DT_RELR)    relr    = d->d_un.d_ptr;
                else if (d->d_tag == DT_RELRSZ)  relrsz  = d->d_un.d_val;
                else if (d->d_tag == DT_RELRENT) relrent = d->d_un.d_val;
            }
            if (rela && relasz && relaent && (relaent == sizeof(Elf64_Rela))){
                uint64_t count = relasz / relaent;
                Elf64_Rela* rel = (Elf64_Rela*)(uintptr_t)(load_base + rela);
                for (uint64_t i = 0; i < count; ++i){
                    uint32_t type = ELF64_R_TYPE(rel[i].r_info);
                    if (type == R_X86_64_RELATIVE){
                        uint64_t* where = (uint64_t*)(uintptr_t)(load_base + rel[i].r_offset);
                        uint64_t  val   = load_base + (uint64_t)rel[i].r_addend;
                        *where = val;
                    } else if (type == R_X86_64_64 || type == R_X86_64_GLOB_DAT) {
                        // Для статического PIE трактуем как base+addend
                        uint64_t* where = (uint64_t*)(uintptr_t)(load_base + rel[i].r_offset);
                        uint64_t  val   = load_base + (uint64_t)rel[i].r_addend;
                        *where = val;
                    }
                }
            }
            if (rel && relsz && relent && (relent == sizeof(Elf64_Rel))){
                uint64_t count = relsz / relent;
                Elf64_Rel* rr = (Elf64_Rel*)(uintptr_t)(load_base + rel);
                for (uint64_t i = 0; i < count; ++i){
                    uint32_t type = ELF64_R_TYPE(rr[i].r_info);
                    if (type == R_X86_64_RELATIVE){
                        uint64_t* where = (uint64_t*)(uintptr_t)(load_base + rr[i].r_offset);
                        // addend хранится по адресу where
                        uint64_t addend = *where;
                        *where = load_base + addend;
                    } else if (type == R_X86_64_64 || type == R_X86_64_GLOB_DAT) {
                        uint64_t* where = (uint64_t*)(uintptr_t)(load_base + rr[i].r_offset);
                        uint64_t addend = *where;
                        *where = load_base + addend;
                    }
                }
            }
            if (relr && relrsz){
                // Применяем RELR по спецификации: чередование адресов и битмапов
                uint64_t entries = relrsz / sizeof(uint64_t);
                uint64_t* p = (uint64_t*)(uintptr_t)(load_base + relr);
                uint64_t base_addr = 0;
                for (uint64_t i = 0; i < entries; ++i){
                    uint64_t e = p[i];
                    if ((e & 1ULL) == 0){
                        base_addr = load_base + e;
                        // сам адрес тоже подвергается относительной релокации
                        uint64_t* where = (uint64_t*)(uintptr_t)base_addr;
                        *where = *where + load_base;
                    } else {
                        // bitmap: биты 1..63 соответствуют последующим словам
                        uint64_t mask = e;
                        for (uint64_t bit = 1; bit < 64; ++bit){
                            if (mask & (1ULL << bit)){
                                uint64_t* where = (uint64_t*)(uintptr_t)(base_addr + bit * 8ULL);
                                *where = *where + load_base;
                            }
                        }
                        base_addr += 64ULL * 8ULL;
                    }
                }
            }
        }
    }

    // Дополнительная проверка: e_entry должен попадать в любой PT_LOAD
    bool entry_ok = false; uint64_t first_load_vaddr = 0; bool have_first=false;
    for (int i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if(!have_first){ first_load_vaddr = ph->p_vaddr; have_first=true; }
        uint64_t seg_size = (ph->p_filesz > ph->p_memsz) ? ph->p_filesz : ph->p_memsz;
        uint64_t start = load_base + ph->p_vaddr;
        uint64_t end   = load_base + ph->p_vaddr + seg_size;
        uint64_t adj_entry = load_base + eh.e_entry;
        if (adj_entry >= start && adj_entry < end) { entry_ok = true; break; }
    }
    if (!entry_ok) {
        uint64_t forced = load_base + (have_first ? first_load_vaddr : (min_ptload_vaddr==~0ULL?0:min_ptload_vaddr));
        PrintfQEMU("[elf] entry 0x%llx not in PT_LOAD, forcing to 0x%llx\n", (unsigned long long)(load_base + eh.e_entry), (unsigned long long)forced);
        eh.e_entry = have_first ? first_load_vaddr : (min_ptload_vaddr==~0ULL?0:min_ptload_vaddr);
    }

    // Заполним auxv-поля для ядра (AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY)
    // Правильно вычислим адрес PHDR в памяти: либо через PT_PHDR, либо конвертируя e_phoff через PT_LOAD, содержащий его
    {
        uint64_t at_phdr_addr = 0;
        // 1) Ищем PT_PHDR
        for (int i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
            if (ph->p_type == 6 /*PT_PHDR*/){
                at_phdr_addr = load_base + ph->p_vaddr;
                break;
            }
        }
        // 2) Если нет PT_PHDR — конвертируем e_phoff (file offset) в VA по PT_LOAD, который его покрывает
        if (at_phdr_addr == 0){
            for (int i = 0; i < eh.e_phnum; ++i) {
                Elf64_Phdr* ph = (Elf64_Phdr*)((uint8_t*)ph_buf + i * eh.e_phentsize);
                if (ph->p_type != PT_LOAD) continue;
                uint64_t off = eh.e_phoff;
                if (off >= ph->p_offset and off < (ph->p_offset + ph->p_filesz)){
                    uint64_t delta = off - ph->p_offset;
                    at_phdr_addr = load_base + ph->p_vaddr + delta;
                    break;
                }
            }
        }
        // 3) Fallback: load_base + e_phoff (если вдруг не попали ни в один PT_LOAD)
        if (at_phdr_addr == 0) at_phdr_addr = load_base + eh.e_phoff;
        elf_last_at_phdr  = at_phdr_addr;
    }
    elf_last_at_phent = eh.e_phentsize;
    elf_last_at_phnum = eh.e_phnum;
    elf_last_at_entry = load_base + eh.e_entry;
    if (elf_last_at_entry == 0) {
        // Жёсткий fallback: первый PT_LOAD как точка входа (обычно 0x400000)
        uint64_t fallback_entry = load_base + (have_first ? first_load_vaddr : (min_ptload_vaddr==~0ULL?0:min_ptload_vaddr));
        elf_last_at_entry = fallback_entry;
        PrintfQEMU("[elf] WARN: at_entry==0, fallback to first/min PT_LOAD: 0x%llx\n",
                   (unsigned long long)elf_last_at_entry);
    }
    elf_last_load_base = load_base;
    // brk: конец PT_LOAD, выровненный по странице
    if (max_load_end) {
        elf_last_brk_base = (max_load_end + 0xFFFULL) & ~0xFFFULL;
    } else {
        elf_last_brk_base = 0;
    }

    kfree(ph_buf);
    fs_close(f);

    // Выделение и маппинг пользовательского стека: фиксированный VA топ и постраничная физическая память
    if (user_stack_size < 16384) user_stack_size = 16384;
    const uint64_t USER_STACK_TOP_VA = 0x30000000ULL; // 768 MiB, далеко от кучи ядра
    uint64_t u_top = USER_STACK_TOP_VA;
    // Добавим запас снизу стека (64 КБ), чтобы избежать раннего #PF при выравнивании и первых push
    uint64_t map_base = u_top - user_stack_size;
    if (map_base > 0x10000ULL) map_base -= 0x10000ULL; else map_base = 0;
    uint64_t s_start = map_base & ~0xFFFULL;
    uint64_t s_end   = (u_top + 0xFFFULL) & ~0xFFFULL;

    PrintfQEMU("[elf] stack map: start=0x%llx end=0x%llx u_top=0x%llx\n",
               (unsigned long long)s_start,
               (unsigned long long)s_end,
               (unsigned long long)u_top);

    for (uint64_t va = s_start; va < s_end; va += 0x1000ULL) {
        void* page_raw = elf_alloc_page4k();
        if (!page_raw) page_raw = kmalloc_aligned(0x1000, 0x1000);
        if (!page_raw) { asm volatile("push %0; popfq"::"r"(saved_rflags):"memory"); return -1; }
        uint64_t page_phys = (uint64_t)page_raw;
        paging_map_page(va, page_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
        memset((void*)(uintptr_t)va, 0, 0x1000);
    }

    if (out_entry) {
        *out_entry = load_base + eh.e_entry;
        if (*out_entry == 0) {
            *out_entry = elf_last_at_entry;
        }
    }
    if (out_user_stack_top) *out_user_stack_top = u_top - 8; // обеспечить RSP%16==8 на входе в _start

    // восстановить флаги прерываний
    asm volatile("push %0; popfq"::"r"(saved_rflags):"memory");
    return 0;
} 