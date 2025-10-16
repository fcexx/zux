#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// loads ELF64 from file path, maps PT_LOAD segments into USER-space,
// allocates user stack (size_bytes), returns entry and top of stack.
// Returns 0 on success, -1 on error.
int elf64_load_process(const char* path, uint64_t user_stack_size,
                                           uint64_t* out_entry, uint64_t* out_user_stack_top);
extern "C" uint64_t elf_last_at_phdr;
extern "C" uint64_t elf_last_at_phent;
extern "C" uint64_t elf_last_at_phnum;
extern "C" uint64_t elf_last_at_entry;
extern "C" uint64_t elf_last_brk_base;
extern "C" uint64_t elf_last_load_base;
// TLS (from pt_tls) for initial thread setup
extern "C" uint64_t elf_last_tls_image_vaddr;
extern "C" uint64_t elf_last_tls_filesz;
extern "C" uint64_t elf_last_tls_memsz;
extern "C" uint64_t elf_last_tls_align;

#ifdef __cplusplus
}
#endif

#endif // ELF_H 