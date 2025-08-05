#ifndef STDINT_H
#define STDINT_H

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

// Boolean type
#ifndef __cplusplus
typedef int bool;
#define true 1
#define false 0
#endif

#endif