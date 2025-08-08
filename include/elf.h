#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Загружает ELF64 из файла path, маппит PT_LOAD сегменты в USER-пространство,
// выделяет стек пользователя (size_bytes), возвращает entry и вершину стека.
// Возвращает 0 при успехе, -1 при ошибке.
int elf64_load_process(const char* path, uint64_t user_stack_size,
                       uint64_t* out_entry, uint64_t* out_user_stack_top);

#ifdef __cplusplus
}
#endif

#endif // ELF_H 