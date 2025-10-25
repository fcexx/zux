#ifndef STDIO_H
#define STDIO_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int vsnprintf(char* buf, size_t size, const char* fmt, va_list ap);
int snprintf(char* buf, size_t size, const char* fmt, ...);
int vsprintf(char* buf, const char* fmt, va_list ap);
int sprintf(char* buf, const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif