#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
void PrintfQEMU(const char* fmt, ...);
#ifdef __cplusplus
}
#endif

void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void PrintQEMU(const char* str);