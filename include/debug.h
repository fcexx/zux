#pragma once

#include <stdint.h>
#include <stdarg.h>

// We're using cpp lol so i dont know the purpose of this
#ifdef __cplusplus
extern "C" {
#endif
void PrintfQEMU(const char* fmt, ...);
const char* k_get_mslog();
int klog_printf(const char* fmt, ...);
int klog_vprintf(const char* fmt, va_list ap);
#ifdef __cplusplus
}
#endif

// Some port kernel funcs
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void outw(uint16_t port, uint16_t val);
uint16_t inw(uint16_t port);
void PrintQEMU(const char* str);