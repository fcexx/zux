#pragma once

#include <stdint.h>

// We're using cpp lol so i dont know the purpose of this
#ifdef __cplusplus
extern "C" {
#endif
void PrintfQEMU(const char* fmt, ...);
#ifdef __cplusplus
}
#endif

// Some port kernel funcs
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void outw(uint16_t port, uint16_t val);
uint16_t inw(uint16_t port);
void PrintQEMU(const char* str);